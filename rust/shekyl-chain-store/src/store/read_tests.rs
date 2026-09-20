// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The committed-chain read surface (S-CHAIN-R, `DRS_E1_SCHAIN_R.md` §3,
//! §7 commits 3–5), pinned read by read against the shapes the plan rules:
//! `AtHeight` above the dense tip and SI-7 below it, `Option` by hash,
//! `TipState` carrying the writer's state outside the `Option`, ranges
//! half-open and clamped, bodies verified against the recorded identity,
//! `RawBlockBytes` a type and not a name — and, on every SI-7 the snapshot
//! returns, the writer **still `Live`**: a read never arms the halt
//! (`DAEMON_REDB_STORE.md` §3.6.2, the read-side half).

use shekyl_chain_rules::{AtHeight, RuleSetId};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot};
use shekyl_units::AtomicUnits;

use super::connect_fixtures::{candidate, connect_chain, facts, judge, spend};
use super::error::{CellFault, StoreError, StoreInvariant};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::Canonical;
use crate::schema::{BLOCK_INFO, CURVE_TREE_ROOTS};

fn h(raw: u64) -> BlockHeight {
    BlockHeight::from_raw(raw)
}

fn is_si7_absent(e: &StoreError, key: &str) -> bool {
    matches!(
        e,
        StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
            key: k,
            fault: CellFault::Absent,
        }) if *k == key
    )
}

// ------------------------------------------------------------------ R1

#[test]
fn tip_on_a_fresh_file_is_none_and_live_not_an_engine_error() {
    let path = tmp("read-tip-fresh");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let snap = store.begin_read().expect("read");
    // The table exists from the seal (A2), so an empty chain is a value.
    assert_eq!(
        snap.tip().expect("tip"),
        TipState {
            recorded: None,
            connect: ConnectState::Live,
        }
    );
    cleanup(&path);
}

#[test]
fn tip_carries_a_genesis_halt_with_nothing_recorded() {
    let path = tmp("read-tip-halted-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Plant `curve_tree_roots[1]` so the genesis connect's SI-4 belt fires
    // at height 0 — a halt with no recorded tip (SCR-18).
    let planted: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_insert_table(CURVE_TREE_ROOTS, StoreInvariant::RootRewritten)?
            .insert(1, CurveTreeRoot::from_bytes([1; 32]).encoded().as_encoded())?;
        Ok(())
    });
    planted.expect("plant");
    let g = candidate(0, BlockHash::NULL, Vec::new());
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        Ok(batch.connect(judge(&view, g)?, facts(0, 0), RuleSetId::GENESIS)?)
    });
    assert!(out.is_err(), "SI-4 refuses the genesis connect");
    let snap = store.begin_read().expect("read");
    let tip = snap.tip().expect("tip");
    assert_eq!(tip.recorded, None, "nothing recorded");
    assert!(
        matches!(tip.connect, ConnectState::Halted { at_height, .. } if at_height == h(0)),
        "and the writer is halted at genesis: {:?}",
        tip.connect
    );
    cleanup(&path);
}

#[test]
fn tip_is_the_last_recorded_block_and_the_writer_is_live() {
    let path = tmp("read-tip-recorded");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let snap = store.begin_read().expect("read");
    let tip = snap.tip().expect("tip");
    assert_eq!(
        tip.recorded.expect("recorded"),
        shekyl_chain_rules::Tip {
            height: h(1),
            hash: hashes[1],
        }
    );
    assert_eq!(tip.connect, ConnectState::Live);
    cleanup(&path);
}

// ------------------------------------------------------------------ R2

#[test]
fn height_of_is_some_for_a_recorded_hash_and_none_otherwise() {
    let path = tmp("read-height-of");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    for (i, hash) in hashes.iter().enumerate() {
        assert_eq!(snap.height_of(hash).expect("read"), Some(h(i as u64)));
    }
    assert_eq!(
        snap.height_of(&BlockHash::from_bytes([0xee; 32]))
            .expect("read"),
        None,
        "by hash, absence has one meaning"
    );
    cleanup(&path);
}

// ------------------------------------------------------------------ R3

#[test]
fn block_info_is_recorded_at_and_below_the_tip_and_above_tip_above_it() {
    let path = tmp("read-block-info");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![spend(0x5e, 2)], vec![]]);
    let snap = store.begin_read().expect("read");
    for height in 0..3u64 {
        let AtHeight::Recorded(info) = snap.block_info(h(height)).expect("read") else {
            panic!("height {height} is recorded");
        };
        assert_eq!(
            info.timestamp,
            shekyl_types::Timestamp::from_raw(1_000 + 60 * height),
            "the fixture's clock"
        );
        assert_eq!(info.cumulative_tx_count, u64::from(height >= 1), "0, 1, 1");
    }
    assert!(matches!(
        snap.block_info(h(3)).expect("read"),
        AtHeight::AboveTip
    ));
    assert!(matches!(
        snap.block_info(h(u64::MAX)).expect("read"),
        AtHeight::AboveTip
    ));
    cleanup(&path);
}

#[test]
fn a_hole_below_the_tip_is_si7_and_does_not_halt_the_writer() {
    let path = tmp("read-hole-no-halt");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    drop(store);
    // Delete `block_info[1]` behind the store's back: a hole below the tip.
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        txn.open_table(BLOCK_INFO)
            .expect("t")
            .remove(1)
            .expect("remove")
            .expect("row 1 existed");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    let e = snap
        .block_info(h(1))
        .expect_err("a hole is SI-7, never AboveTip");
    assert!(is_si7_absent(&e, "block_info"), "{e}");
    // The read-side half of §3.6.2: the snapshot returned the fault and
    // armed nothing. A `BatchView` read of the same row would have poisoned
    // its batch and halted the writer.
    assert_eq!(store.connect_state(), ConnectState::Live);
    assert_eq!(snap.tip().expect("tip").connect, ConnectState::Live);
    // And the same range read reports the hole as that item's error, not
    // as an early end.
    let AtHeight::Recorded(rows) = snap.block_infos(h(0)..h(3)).expect("range") else {
        panic!("start 0 is at or below the tip");
    };
    let rows: Vec<_> = rows.collect();
    assert_eq!(rows.len(), 3);
    assert!(rows[0].is_ok() && rows[2].is_ok());
    assert!(is_si7_absent(
        rows[1].as_ref().expect_err("the hole"),
        "block_info"
    ));
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

// ------------------------------------------------------------------ R4

#[test]
fn block_infos_is_above_tip_when_the_start_is_and_clamps_the_end_otherwise() {
    let path = tmp("read-block-infos");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    // Start above the tip: the typed arm, matched — not an empty iterator.
    assert!(matches!(
        snap.block_infos(h(3)..h(10)).expect("range"),
        AtHeight::AboveTip
    ));
    // Start at or below, end past the tip: clamped to `tip + 1`, ascending.
    let AtHeight::Recorded(rows) = snap.block_infos(h(1)..h(10)).expect("range") else {
        panic!("start 1 is recorded");
    };
    let heights: Vec<u64> = rows.map(|r| r.expect("row").0.to_raw()).collect();
    assert_eq!(heights, [1, 2]);
    // Half-open: `start..start + count` yields `count` rows (SCR-20).
    let AtHeight::Recorded(rows) = snap.block_infos(h(0)..h(2)).expect("range") else {
        panic!("start 0 is recorded");
    };
    assert_eq!(rows.count(), 2);
    // An empty half-open range at or below the tip is an empty iterator,
    // not `AboveTip`: the start *is* recorded.
    let AtHeight::Recorded(rows) = snap.block_infos(h(1)..h(1)).expect("range") else {
        panic!("start 1 is recorded");
    };
    assert_eq!(rows.count(), 0);
    // Empty chain: every start is above the (absent) tip.
    let empty = tmp("read-block-infos-empty");
    let fresh = ChainStore::create(&empty, EPOCH).expect("create");
    assert!(matches!(
        fresh
            .begin_read()
            .expect("read")
            .block_infos(h(0)..h(1))
            .expect("range"),
        AtHeight::AboveTip
    ));
    cleanup(&empty);
    cleanup(&path);
}

// ------------------------------------------------------------------ R5–R7

#[test]
fn block_returns_the_body_verified_against_the_recorded_identity() {
    let path = tmp("read-block");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let snap = store.begin_read().expect("read");
    let AtHeight::Recorded(body) = snap.block(h(1)).expect("read") else {
        panic!("height 1 is recorded");
    };
    assert_eq!(body.hash, hashes[1]);
    assert_eq!(
        body.block.hash(),
        hashes[1],
        "the body hashes to its identity"
    );
    assert_eq!(body.block.transaction_hashes.len(), 1);
    assert!(matches!(
        snap.block(h(2)).expect("read"),
        AtHeight::AboveTip
    ));
    cleanup(&path);
}

#[test]
fn a_rewritten_blob_is_si7_on_block_and_blocks_but_block_blob_still_hands_out_the_bytes() {
    let path = tmp("read-rewritten-blob");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![], vec![]]);
    // Rewrite `blocks[1]` to a different, parseable block: the identity on
    // `block_info[1]` no longer matches.
    let impostor = candidate(1, BlockHash::from_bytes([0x77; 32]), Vec::new())
        .block
        .serialize();
    let out: Result<(), TestErr> = store.write(|batch| {
        batch.open_upsert_table(crate::schema::BLOCKS)?.upsert(
            1,
            crate::codec::Raw::<crate::codec::BlockBody>::new(&impostor),
        )?;
        Ok(())
    });
    out.expect("rewrite");
    let snap = store.begin_read().expect("read");
    let e = snap.block(h(1)).expect_err("verified read refuses");
    assert!(
        matches!(
            e,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "blocks",
                fault: CellFault::Undecodable(_),
            })
        ),
        "{e}"
    );
    let AtHeight::Recorded(rows) = snap.blocks(h(0)..h(3)).expect("range") else {
        panic!("start 0 is recorded");
    };
    let rows: Vec<_> = rows.collect();
    assert!(
        rows[0].is_ok() && rows[2].is_ok(),
        "the neighbours are fine"
    );
    assert!(rows[1].is_err(), "the rewritten row is that item's fault");
    // The unverified reader hands out exactly the bytes on disk (Q2): the
    // sync path forwards them, and a consensus caller cannot get here
    // without naming `RawBlockBytes`.
    let AtHeight::Recorded(raw) = snap.block_blob(h(1)).expect("blob") else {
        panic!("height 1 is recorded");
    };
    assert_eq!(raw.into_wire_bytes(), impostor);
    // And none of it halted the writer.
    assert_eq!(store.connect_state(), ConnectState::Live);
    cleanup(&path);
}

#[test]
fn blocks_range_clamps_at_the_tip_and_yields_the_last_height_of_a_half_open_range() {
    let path = tmp("read-blocks-range");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(&store, &[vec![], vec![], vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    // `start..start + count` yields `count` rows, the last one included —
    // the inclusive-`h2` port hazard (SCR-20).
    let (start, count) = (1u64, 3u64);
    let AtHeight::Recorded(rows) = snap.blocks(h(start)..h(start + count)).expect("range") else {
        panic!("start 1 is recorded");
    };
    let got: Vec<(u64, BlockHash)> = rows
        .map(|r| {
            let (height, body) = r.expect("row");
            (height.to_raw(), body.block.hash())
        })
        .collect();
    assert_eq!(got.len(), usize::try_from(count).expect("small"));
    assert_eq!(
        got.last().expect("three rows").0,
        start + count - 1,
        "the last height is yielded"
    );
    for (height, hash) in &got {
        assert_eq!(*hash, hashes[usize::try_from(*height).expect("small")]);
    }
    // End past the tip clamps; start past the tip is the typed arm.
    let AtHeight::Recorded(rows) = snap.blocks(h(2)..h(100)).expect("range") else {
        panic!("start 2 is recorded");
    };
    assert_eq!(rows.count(), 2);
    assert!(matches!(
        snap.blocks(h(4)..h(5)).expect("range"),
        AtHeight::AboveTip
    ));
    cleanup(&path);
}

#[test]
fn block_blob_above_the_tip_is_above_tip_and_a_hole_is_si7() {
    let path = tmp("read-blob-classify");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![]]);
    drop(store);
    {
        let db = redb::Database::open(&path).expect("raw open");
        let txn = db.begin_write().expect("raw write");
        txn.open_table(crate::schema::BLOCKS)
            .expect("t")
            .remove(0)
            .expect("remove")
            .expect("row 0 existed");
        txn.commit().expect("commit");
    }
    let store = ChainStore::create(&path, EPOCH).expect("reopen");
    let snap = store.begin_read().expect("read");
    assert!(matches!(
        snap.block_blob(h(2)).expect("read"),
        AtHeight::AboveTip
    ));
    let e = snap.block_blob(h(0)).expect_err("a hole below the tip");
    assert!(is_si7_absent(&e, "blocks"), "{e}");
    assert_eq!(
        store.connect_state(),
        ConnectState::Live,
        "a read never arms the halt"
    );
    cleanup(&path);
}

// ------------------------------------------------------------------ R8–R9 and the fold reads

/// Connect three blocks handing `burned` per height, so R8/R9 have a fold
/// to read: genesis records none whatever it is handed (the `h > 0` half of
/// the C++ guard), a zero writes no row.
fn connect_burning(store: &ChainStore, burns: &[u64]) {
    let mut previous = BlockHash::NULL;
    let mut cands = Vec::new();
    for h in 0..burns.len() as u64 {
        let cand = candidate(h, previous, Vec::new());
        previous = cand.block.hash();
        cands.push(cand);
    }
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for (h, cand) in cands.into_iter().enumerate() {
            batch.connect(
                judge(&view, cand)?,
                facts(h as u64, burns[h]),
                RuleSetId::GENESIS,
            )?;
        }
        Ok(())
    });
    out.expect("chain connects");
}

#[test]
fn block_burn_reads_zero_for_a_block_with_no_row_and_the_amount_otherwise() {
    let path = tmp("read-block-burn");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // genesis is handed 9 and records none; block 1 burns 0 (no row);
    // block 2 burns 25 (a row).
    connect_burning(&store, &[9, 0, 25]);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.block_burn(h(0)).expect("read"),
        AtHeight::Recorded(AtomicUnits::from_raw(0)),
        "genesis: no row"
    );
    assert_eq!(
        snap.block_burn(h(1)).expect("read"),
        AtHeight::Recorded(AtomicUnits::from_raw(0)),
        "zero burn: no row"
    );
    assert_eq!(
        snap.block_burn(h(2)).expect("read"),
        AtHeight::Recorded(AtomicUnits::from_raw(25))
    );
    assert_eq!(snap.block_burn(h(3)).expect("read"), AtHeight::AboveTip);
    cleanup(&path);
}

#[test]
fn block_burn_on_a_chain_that_has_never_burned_is_zero_not_an_engine_error() {
    let path = tmp("read-block-burn-never");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![]]);
    let snap = store.begin_read().expect("read");
    // SCR-17's case: the table exists from the seal (A2), so the absent row
    // is the writer's zero, not `TableDoesNotExist`.
    assert_eq!(
        snap.block_burn(h(1)).expect("read"),
        AtHeight::Recorded(AtomicUnits::ZERO)
    );
    assert_eq!(
        snap.total_burned().expect("read"),
        AtomicUnits::ZERO,
        "absent cell is 0"
    );
    cleanup(&path);
}

#[test]
fn total_burned_is_the_sum_connect_folded() {
    let path = tmp("read-total-burned");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_burning(&store, &[9, 3, 25]);
    let snap = store.begin_read().expect("read");
    // Genesis's 9 is not folded (no row, no pre-image); 3 + 25 is.
    assert_eq!(
        snap.total_burned().expect("read"),
        AtomicUnits::from_raw(28)
    );
    cleanup(&path);
}

#[test]
fn the_fold_reads_return_exactly_what_connect_wrote() {
    let path = tmp("read-fold-reads");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(
        &store,
        &[
            vec![],
            vec![spend(0x5e, 1), spend(0x5f, 1)],
            vec![spend(0x60, 1)],
        ],
    );
    let snap = store.begin_read().expect("read");
    for (height, cum) in [(0u64, 0u64), (1, 2), (2, 3)] {
        assert_eq!(
            snap.cumulative_tx_count(h(height)).expect("read"),
            AtHeight::Recorded(cum)
        );
        assert_eq!(
            snap.long_term_effective_median(h(height)).expect("read"),
            AtHeight::Recorded(facts(height, 0).long_term_effective_median.value),
            "the median handed FOR {height}, at {height}"
        );
    }
    assert_eq!(
        snap.cumulative_tx_count(h(3)).expect("read"),
        AtHeight::AboveTip
    );
    assert_eq!(
        snap.long_term_effective_median(h(3)).expect("read"),
        AtHeight::AboveTip
    );
    cleanup(&path);
}

// ------------------------------------------------ DRS-E2 RD-F5: the digest

#[test]
fn an_empty_file_digests_as_no_hashes_no_spends_and_the_empty_root() {
    let path = tmp("read-digest-empty");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.logical_state_digest_v0().expect("digest"),
        crate::digest_v0::digest_v0(&[], &[], CurveTreeRoot::EMPTY.as_bytes())
    );
    cleanup(&path);
}

#[test]
fn the_redb_digest_is_the_hasher_over_the_files_three_families() {
    // The same three families the C++ walker hands the FFI, read from the
    // redb file: height-ordered block hashes, the spent-key set, and the
    // live root — `curve_tree_roots[tip + 1]`, the state after the tip's
    // drain (SCW-19), which is `facts(tip).root_after`.
    let path = tmp("read-digest-chain");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let hashes = connect_chain(
        &store,
        &[vec![], vec![spend(0x5e, 1)], vec![spend(0x5f, 1)]],
    );
    let snap = store.begin_read().expect("read");
    let by_hand = {
        let blocks: Vec<[u8; 32]> = hashes.iter().map(|h| *h.as_bytes()).collect();
        let spent = [[0x5e; 32], [0x5f; 32]];
        crate::digest_v0::digest_v0(&blocks, &spent, facts(2, 0).root_after.value.as_bytes())
    };
    assert_eq!(snap.logical_state_digest_v0().expect("digest"), by_hand);
    // Order-insensitive in the spent family, as the hasher promises.
    let swapped = crate::digest_v0::digest_v0(
        &hashes.iter().map(|h| *h.as_bytes()).collect::<Vec<_>>(),
        &[[0x5f; 32], [0x5e; 32]],
        facts(2, 0).root_after.value.as_bytes(),
    );
    assert_eq!(by_hand, swapped);
    cleanup(&path);
}

#[test]
fn the_digest_moves_when_any_family_moves() {
    // Negative control (rule 47): a comparison that cannot go red proves
    // nothing. One more block with one more spend changes it; the previous
    // chain's digest is not the new one.
    let path = tmp("read-digest-moves");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![], vec![spend(0x5e, 1)]]);
    let before = store
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");
    let tip = store
        .begin_read()
        .expect("read")
        .tip()
        .expect("tip")
        .recorded
        .expect("two blocks");
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let cand = candidate(2, tip.hash, vec![spend(0x60, 1)]);
        batch.connect(judge(&view, cand)?, facts(2, 0), RuleSetId::GENESIS)?;
        Ok(())
    });
    out.expect("connects");
    let after = store
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");
    assert_ne!(before, after);
    cleanup(&path);
}
