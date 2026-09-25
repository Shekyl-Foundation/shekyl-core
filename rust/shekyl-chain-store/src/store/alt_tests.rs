// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-ALT: AL1–AL7 on the batch and the snapshot, the typed refusals, SI-7
//! on a corrupt row, and the switch as one transaction (SAL-1).

use shekyl_chain_rules::RuleSet;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight, BlockWeight};
use shekyl_units::AtomicUnits;

use super::connect_fixtures::{candidate, connect_chain, facts, judge, spend};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{forged, AltBlock, AltBlockFacts};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::ALT_BLOCKS;

fn alt(height: u64, block: Vec<u8>, witness: Option<Vec<u8>>) -> AltBlock {
    AltBlock::checked(
        AltBlockFacts {
            height: BlockHeight::from_raw(height),
            block_weight: Some(BlockWeight::from_raw(300 + height)),
            cumulative_difficulty: CumulativeDifficulty::from_raw(1_000 + u128::from(height)),
            coins_generated: AtomicUnits::from_raw(50 * height),
        },
        block,
        witness,
    )
    .expect("fixture record")
}

/// A block off the main chain at `height`, distinguished by its listed
/// transaction, and its bytes.
fn side_block(height: u64, previous: BlockHash, key_image: usize) -> (BlockHash, Vec<u8>) {
    let cand = candidate(height, previous, vec![spend(key_image, 1)]);
    (cand.block.hash(), cand.block.serialize())
}

fn tip_height(store: &ChainStore) -> Option<u64> {
    let snap = store.begin_read().expect("read");
    snap.tip().expect("tip").recorded.map(|t| t.height.to_raw())
}

/// The recorded hash at `height`, from `block_info`.
fn hash_at(store: &ChainStore, height: u64) -> Option<BlockHash> {
    let snap = store.begin_read().expect("read");
    match snap
        .block_info(BlockHeight::from_raw(height))
        .expect("info")
    {
        shekyl_chain_rules::AtHeight::Recorded(info) => Some(info.hash),
        shekyl_chain_rules::AtHeight::AboveTip => None,
    }
}

#[test]
fn insert_read_enumerate_remove_and_drop() {
    let path = tmp("alt-ops");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![], vec![]]);
    let (a, a_bytes) = side_block(1, main[0], 3);
    let (b, b_bytes) = side_block(2, a, 4);
    let witness = vec![0xA5; 40];

    let out: Result<(), TestErr> = store.write(|batch| {
        batch.insert_alt_block(&a, &alt(1, a_bytes.clone(), None))?;
        batch.insert_alt_block(&b, &alt(2, b_bytes.clone(), Some(witness.clone())))?;
        // The batch sees its own writes.
        assert!(batch.has_alt_block(&a)?);
        assert_eq!(batch.alt_block_count()?, 2);
        assert_eq!(
            batch
                .alt_block(&b)?
                .as_ref()
                .and_then(AltBlock::attestation_witness),
            Some(witness.as_slice())
        );
        Ok(())
    });
    out.expect("insert");

    {
        let snap = store.begin_read().expect("read");
        assert!(snap.has_alt_block(&a).expect("has"));
        assert!(
            !snap.has_alt_block(&main[1]).expect("has"),
            "a main-chain hash is not an alt block"
        );
        assert_eq!(snap.alt_block(&main[1]).expect("get"), None);
        let got = snap.alt_block(&a).expect("get").expect("held");
        assert_eq!(got.block(), a_bytes.as_slice());
        assert_eq!(got.attestation_witness(), None);
        assert_eq!(got.height(), BlockHeight::from_raw(1));
        assert_eq!(snap.alt_block_count().expect("len"), 2);
        let all = snap.alt_blocks().expect("entries");
        assert_eq!(all.len(), 2);
        assert!(all
            .iter()
            .any(|e| e.id == a && e.block.attestation_witness().is_none()));
        assert!(all
            .iter()
            .any(|e| e.id == b && e.block.attestation_witness() == Some(witness.as_slice())));
        // Key order is the table's, never insertion order.
        let keys: Vec<LmdbHashKey> = all
            .iter()
            .map(|e| LmdbHashKey::from_bytes(*e.id.as_bytes()))
            .collect();
        assert!(keys.windows(2).all(|w| w[0] < w[1]));
    }

    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.remove_alt_block(&a)?));
    out.expect("remove");
    {
        let snap = store.begin_read().expect("read");
        assert!(!snap.has_alt_block(&a).expect("has"));
        assert!(snap.has_alt_block(&b).expect("has"));
    }

    let out: Result<u64, TestErr> = store.write(|batch| {
        batch.insert_alt_block(&a, &alt(1, a_bytes.clone(), None))?;
        Ok(batch.drop_alt_blocks()?)
    });
    assert_eq!(out, Ok(2), "drop reports how many it removed");
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.alt_block_count().expect("len"), 0);
    assert!(snap.alt_blocks().expect("entries").is_empty());
    assert!(
        store.connect_state().is_live(),
        "alt writes are not chain work; nothing halts"
    );
    cleanup(&path);
}

#[test]
fn insert_of_a_held_hash_and_remove_of_an_absent_one_are_refusals() {
    let path = tmp("alt-refusals");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![]]);
    let (a, a_bytes) = side_block(1, main[0], 5);

    let out: Result<(), TestErr> =
        store.write(|batch| Ok(batch.insert_alt_block(&a, &alt(1, a_bytes.clone(), None))?));
    out.expect("first insert");

    let out: Result<(), TestErr> =
        store.write(|batch| Ok(batch.insert_alt_block(&a, &alt(1, a_bytes.clone(), None))?));
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(AltCannot::AlreadyHeld).to_string()
        )),
        "CEN-K3's belt, typed"
    );
    assert_eq!(
        StoreError::from(AltCannot::AlreadyHeld).class(),
        ErrorClass::Cannot,
        "a refusal, not a fault"
    );

    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.remove_alt_block(&main[0])?));
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(AltCannot::NotHeld).to_string()
        )),
        "removing what is not held is a caller-contract violation"
    );

    // Neither refusal is fatal: the store still holds `a` and still writes.
    let snap = store.begin_read().expect("read");
    assert!(snap.has_alt_block(&a).expect("has"));
    assert!(store.connect_state().is_live());
    cleanup(&path);
}

#[test]
fn a_row_that_does_not_decode_is_si7_on_both_readers() {
    let path = tmp("alt-corrupt");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    connect_chain(&store, &[vec![]]);
    let bad = BlockHash::from_bytes([0xBD; 32]);
    let out: Result<(), TestErr> = store.write(|batch| {
        batch
            .txn()
            .open_table(ALT_BLOCKS)
            .map_err(|e| StoreError::from(EngineError::Table(e)))?
            .insert(
                LmdbHashKey::from_bytes(*bad.as_bytes()),
                forged::<AltBlock>(&[0xFF; 9]),
            )
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        Ok(())
    });
    out.expect("plant");

    let snap = store.begin_read().expect("read");
    let is_si7 = |e: &StoreError| {
        matches!(
            e,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "alt_blocks",
                fault: CellFault::Undecodable(_),
            })
        )
    };
    assert!(is_si7(&snap.alt_block(&bad).expect_err("corrupt")));
    assert!(is_si7(&snap.alt_blocks().expect_err("corrupt")));
    // Membership does not decode, so it still answers.
    assert!(snap.has_alt_block(&bad).expect("has"));
    assert!(
        store.connect_state().is_live(),
        "a snapshot read arms nothing"
    );

    // The batch-side read arms the poison: a switch that read a corrupt alt
    // row does not commit, and the writer halts.
    let out: Result<(), TestErr> = store.write(|batch| {
        let e = batch.alt_block(&bad).expect_err("corrupt");
        assert!(is_si7(&e));
        Ok(())
    });
    assert!(out.is_err(), "the poisoned batch refuses to commit");
    cleanup(&path);
}

/// SAL-1: pop to the split, demote, promote, remove — one closure. Then the
/// same closure failing at its last step, and nothing of it landed.
#[test]
fn a_switch_is_one_transaction_or_none_of_it() {
    let path = tmp("alt-switch");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Main chain: 0 — 1 — 2. A competing block 2' on 1 is held as an alt.
    let main = connect_chain(&store, &[vec![], vec![spend(9, 1)], vec![spend(10, 1)]]);
    let main_2_bytes = candidate(2, main[1], vec![spend(10, 1)]).block.serialize();
    let alt_cand = candidate(2, main[1], vec![spend(11, 1)]);
    let alt_2 = alt_cand.block.hash();
    let alt_witness = vec![0x5A; 40];
    let out: Result<(), TestErr> = store.write(|batch| {
        Ok(batch.insert_alt_block(
            &alt_2,
            &alt(2, alt_cand.block.serialize(), Some(alt_witness.clone())),
        )?)
    });
    out.expect("hold 2'");

    // The switch to 2': demote 2, promote 2'.
    let out: Result<Vec<u8>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // Read what the switch is about to change, through the batch.
        let promoted = batch.alt_block(&alt_2)?.expect("2' is held");
        let popped = batch.pop()?;
        assert_eq!(popped.height, BlockHeight::from_raw(2));
        batch.insert_alt_block(&main[2], &alt(2, main_2_bytes.clone(), None))?;
        batch.connect(
            judge(&view, candidate(2, main[1], vec![spend(11, 1)]))?,
            facts(2, 0),
            RuleSet::GENESIS,
        )?;
        batch.remove_alt_block(&alt_2)?;
        Ok(promoted.attestation_witness().expect("witness").to_vec())
    });
    assert_eq!(
        out,
        Ok(alt_witness),
        "the promoted block's witness travels out of the switch"
    );
    assert_eq!(tip_height(&store), Some(2));
    assert_eq!(hash_at(&store, 2), Some(alt_2));
    {
        let snap = store.begin_read().expect("read");
        assert!(
            snap.has_alt_block(&main[2]).expect("has"),
            "the demoted block is an alt block"
        );
        assert!(
            !snap.has_alt_block(&alt_2).expect("has"),
            "the promoted block is not"
        );
        assert_eq!(snap.alt_block_count().expect("len"), 1);
    }

    // The same switch back, failing at its last step: nothing landed.
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        batch.pop()?;
        batch.insert_alt_block(&alt_2, &alt(2, alt_cand.block.serialize(), None))?;
        batch.connect(
            judge(&view, candidate(2, main[1], vec![spend(10, 1)]))?,
            facts(2, 0),
            RuleSet::GENESIS,
        )?;
        batch.remove_alt_block(&main[2])?;
        // A refusal on a hash never held aborts the whole switch.
        batch.remove_alt_block(&main[0])?;
        Ok(())
    });
    assert_eq!(
        out,
        Err(TestErr::Store(
            StoreError::from(AltCannot::NotHeld).to_string()
        ))
    );
    assert_eq!(tip_height(&store), Some(2));
    assert_eq!(hash_at(&store, 2), Some(alt_2), "the pop did not land");
    let snap = store.begin_read().expect("read");
    assert!(
        snap.has_alt_block(&main[2]).expect("has"),
        "the remove did not land"
    );
    assert!(
        !snap.has_alt_block(&alt_2).expect("has"),
        "the insert did not land"
    );
    assert!(store.connect_state().is_live(), "a refusal is not a halt");
    cleanup(&path);
}
