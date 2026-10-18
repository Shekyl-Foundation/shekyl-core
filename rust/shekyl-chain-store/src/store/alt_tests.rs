// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S-ALT: AL1–AL7 on the batch and the snapshot, the typed refusals, SI-7
//! on a corrupt row, and the switch as one transaction (SAL-1). AL1 takes
//! the cheap tier's verdict (DRS-E5 a4, `AltValid → AL1`), so every row
//! these tests hold went through [`admitted`]: K2's walk, the stitched
//! view, `form`, `alt_against`. Rows that must sit *around* that boundary
//! — a corrupt cell, a mis-keyed row — are planted through the raw table
//! ([`plant`]), which is what SI-7 is about.

use shekyl_chain_rules::{alt_against, AltValid, RuleSet, Trust};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{BlockHash, BlockHeight, BlockWeight};

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::Candidate;
use shekyl_harness_spender::MinerWallet;
use shekyl_harness_wallet::coinbase::repay;

use super::connect_fixtures::{
    at, candidate, candidate_over, connect_chain, formed, judge, root_going_into, spend,
    spendable_prefix, FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;
use crate::codec::{forged, AltBlock, AltBlockFacts, AltBodies, Canonical, CodecError, Encoded};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{ALT_BLOCKS, ALT_BLOCK_BODIES};

/// `BlockHeight::from_raw`, short enough for a fixture call.
pub(super) const fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

/// A row from bare facts, for planting around AL1 (`AltBlock::checked`;
/// AL1 itself takes no row). The facts are fixture literals: a planted
/// row's bookkeeping is whatever the test needs it to be.
pub(super) fn alt(height: BlockHeight, block: &[u8], witness: Option<Vec<u8>>) -> AltBlock {
    let raw = height.to_raw();
    AltBlock::checked(
        AltBlockFacts {
            height,
            block_weight: BlockWeight::from_raw(300 + raw),
            cumulative_difficulty: CumulativeDifficulty::from_raw(1_000 + u128::from(raw)),
            pow: crate::codec::RecordedPow {
                seed: shekyl_types::BlockHash::NULL,
                pow: shekyl_types::PowHash::from_bytes([0; 32]),
            },
        },
        block,
        witness,
    )
    .expect("fixture record")
}

/// Write `row` under `key` through the raw table — around AL1's boundary,
/// which is the only way a row AL1 would not have written reaches the
/// file. What the SI-7 and orphan fixtures need.
pub(super) fn plant(store: &ChainStore, key: BlockHash, row: &AltBlock) {
    plant_bytes(store, key, row.encoded().as_encoded());
}

/// [`plant`] for bytes that need not be a row at all (the SI-7 fixture).
pub(super) fn plant_bytes(store: &ChainStore, key: BlockHash, cell: Encoded<'_, AltBlock>) {
    let out: Result<(), TestErr> = store.write(|batch| {
        batch
            .txn()
            .open_table(ALT_BLOCKS)
            .map_err(|e| StoreError::from(EngineError::Table(e)))?
            .insert(LmdbHashKey::from_bytes(*key.as_bytes()), cell)
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        Ok(())
    });
    out.expect("plant");
}

/// A block off the main chain at `height` on `previous`, distinguished by
/// its listed transaction. The cheap tier judges the header and the body's
/// pairing, never a listed transaction (that is promotion's — CEN-K4), so
/// the listed body is the harness's spend-shaped filler — a named key
/// image, no proof — not a spend built against a tree; nothing in the tier
/// reads it as one.
pub(super) fn side_candidate(
    height: BlockHeight,
    previous: BlockHash,
    key_image: usize,
) -> Candidate {
    // Signed: `form` runs the signature sequence at every listed slot
    // (2026-10-16); the filler's proof is unverified here (no reference
    // claim at offer) and refused at promotion, which these tests never
    // reach.
    let filler = fixture::signed(fixture::spend(fixture::point(key_image), 2));
    candidate(height.to_raw(), previous, vec![filler])
}

/// [`side_candidate`]'s identity and bytes, for a planted row.
pub(super) fn side_block(
    height: BlockHeight,
    previous: BlockHash,
    key_image: usize,
) -> (BlockHash, Vec<u8>) {
    let cand = side_candidate(height, previous, key_image);
    (cand.block.hash(), cand.block.serialize())
}

/// `candidate` carrying `witness` as its attestation sidecar (CW-2: the
/// witness rides in the alt row the tier's verdict becomes).
pub(super) fn with_witness(candidate: Candidate, witness: &[u8]) -> Candidate {
    candidate.with_attestation_witness(Some(
        AttestationWitness::new(witness.to_vec()).expect("a fixture witness is well-formed"),
    ))
}

/// The cheap tier over `snap` — what AL1 takes. CEN-K2's walk from the
/// candidate's parent ([`AltChain::build`]), the stitched view, `form`
/// claiming the seed that view answers, then `alt_against` over the view,
/// which names its own fork. The token is branded to that `AltView`, so
/// `snap` has to outlive it through `insert_alt_block`. Panics where a
/// fixture would be wrong: the parent does not link, a row of the tier
/// refuses, the view faults.
pub(super) fn admitted<'s>(
    snap: &'s ReadSnapshot<'s>,
    candidate: Candidate,
) -> AltValid<'s, AltView<'s>> {
    let chain = AltChain::build(snap, &candidate.block.header.previous)
        .expect("the fixture's parent links to the recorded chain");
    let view = AltView::new(snap, chain);
    let formed = formed(&view, candidate).expect("the stitched view answers the seed");
    match alt_against(formed, &view, &RuleSet::GENESIS, &Trust::UNANCHORED) {
        Ok(Ok(valid)) => valid,
        Ok(Err(refused)) => panic!("the fixture satisfies every row of the tier: {refused}"),
        Err(fault) => panic!("the stitched view answers: {fault}"),
    }
}

/// Judge `candidate` on a fresh snapshot and insert it. The snapshot stays
/// live through the write, which is what the verdict's brand requires.
fn insert_admitted(store: &ChainStore, candidate: Candidate) -> Result<(), TestErr> {
    let snap = store.begin_read().expect("read");
    let valid = admitted(&snap, candidate);
    store.write(|batch| Ok(batch.insert_alt_block(valid)?))
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
    let main = connect_chain(&store, &[vec![], vec![]]).hashes;
    let a_cand = side_candidate(h(1), main[0], 3);
    let (a, a_bytes) = (a_cand.block.hash(), a_cand.block.serialize());
    let witness = vec![0xA5; 40];

    // `a` first: `b`'s chain walks through `a`'s row, so `b` is judged on a
    // snapshot that holds it (K2 — the tier reads what the store holds).
    insert_admitted(&store, a_cand).expect("insert a");
    let b_cand = with_witness(side_candidate(h(2), a, 4), &witness);
    let b = b_cand.block.hash();
    let judged = store.begin_read().expect("read");
    let b_valid = admitted(&judged, b_cand);
    assert_eq!(b_valid.height(), h(2), "derived over the stitched chain");
    let out: Result<(), TestErr> = store.write(|batch| {
        batch.insert_alt_block(b_valid)?;
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
    out.expect("insert b");

    {
        let snap = store.begin_read().expect("read");
        assert!(snap.has_alt_block(&a).expect("has"));
        assert!(
            !snap.has_alt_block(&main[1]).expect("has"),
            "a main-chain hash is not an alt block"
        );
        assert_eq!(snap.alt_block(&main[1]).expect("get"), None);
        let got = snap.alt_block(&a).expect("get").expect("held");
        assert_eq!(
            got.block().serialize(),
            a_bytes,
            "handed out parsed, not as bytes"
        );
        assert_eq!(got.block().hash(), a, "the key is the block's identity");
        assert_eq!(got.attestation_witness(), None);
        assert_eq!(got.height(), BlockHeight::from_raw(1));
        assert!(
            got.block_weight().to_raw() > 0,
            "the row's weight is the one the tier measured"
        );
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

    // `a` again, judged afresh: the tier does not know the store once held
    // it, and the store no longer does.
    let judged = store.begin_read().expect("read");
    let a_again = admitted(&judged, side_candidate(h(1), main[0], 3));
    let out: Result<u64, TestErr> = store.write(|batch| {
        batch.insert_alt_block(a_again)?;
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

/// Plant `bodies` under `key` in `alt_block_bodies` alone, around AL1.
fn plant_bodies(store: &ChainStore, key: BlockHash, bodies: &AltBodies) {
    let out: Result<(), TestErr> = store.write(|batch| {
        batch
            .txn()
            .open_table(ALT_BLOCK_BODIES)
            .map_err(|e| StoreError::from(EngineError::Table(e)))?
            .insert(
                LmdbHashKey::from_bytes(*key.as_bytes()),
                bodies.encoded().as_encoded(),
            )
            .map_err(|e| StoreError::from(EngineError::Storage(e)))?;
        Ok(())
    });
    out.expect("plant bodies");
}

/// The bodies are consensus data held with the row (the review of #1102,
/// B1): AL1 writes the verdict's listed bodies, AL8 reads them back in
/// listed order and holds them to the row, and AL2, AL3 and the death rule
/// remove them with it. A row without its bodies, bodies without a row,
/// and bodies that are not the header's listed transactions are SI-7.
#[test]
fn the_bodies_are_written_read_and_removed_with_the_row() {
    let path = tmp("alt-bodies");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![], vec![]]).hashes;
    let a_cand = side_candidate(h(1), main[0], 3);
    let (a, a_listed) = (a_cand.block.hash(), a_cand.transactions.clone());
    assert!(!a_listed.is_empty(), "the fixture lists a body");
    insert_admitted(&store, a_cand).expect("insert a");
    let b_cand = side_candidate(h(2), a, 4);
    let (b, b_listed) = (b_cand.block.hash(), b_cand.transactions.clone());
    insert_admitted(&store, b_cand).expect("insert b");
    {
        let snap = store.begin_read().expect("read");
        let got = snap.alt_block_bodies(&a).expect("read").expect("held");
        assert_eq!(got.transactions(), a_listed.as_slice());
        assert_eq!(snap.alt_block_bodies(&main[1]).expect("read"), None);
    }

    // The death rule's sweep: at or below height 1, `a` and its bodies.
    let out: Result<u64, TestErr> = store.write(|batch| Ok(batch.retire_alt_blocks(h(1))?));
    assert_eq!(out, Ok(1));
    {
        let snap = store.begin_read().expect("read");
        assert_eq!(snap.alt_block_bodies(&a).expect("both gone"), None);
        let got = snap.alt_block_bodies(&b).expect("read").expect("held");
        assert_eq!(got.transactions(), b_listed.as_slice());
    }

    // AL2 takes the bodies with the row.
    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.remove_alt_block(&b)?));
    out.expect("remove");
    assert_eq!(
        store
            .begin_read()
            .expect("read")
            .alt_block_bodies(&b)
            .expect("both gone"),
        None
    );

    // AL3 too.
    let judged = store.begin_read().expect("read");
    let again = admitted(&judged, side_candidate(h(1), main[0], 3));
    let out: Result<u64, TestErr> = store.write(|batch| {
        batch.insert_alt_block(again)?;
        Ok(batch.drop_alt_blocks()?)
    });
    assert_eq!(out, Ok(1));
    assert_eq!(
        store
            .begin_read()
            .expect("read")
            .alt_block_bodies(&a)
            .expect("both gone"),
        None
    );

    // The belts. A row without its bodies:
    let row_only = side_candidate(h(1), main[0], 5);
    let row_id = row_only.block.hash();
    plant(
        &store,
        row_id,
        &alt(h(1), &row_only.block.serialize(), None),
    );
    let is_si7 = |e: StoreError, cell: &str| {
        matches!(
            e,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt { key, .. }) if key == cell
        )
    };
    let snap = store.begin_read().expect("read");
    assert!(is_si7(
        snap.alt_block_bodies(&row_id).expect_err("no bodies"),
        "alt_block_bodies"
    ));
    drop(snap);
    // Bodies that are not the header's:
    plant_bodies(&store, row_id, &AltBodies::of(b_listed));
    let snap = store.begin_read().expect("read");
    assert!(is_si7(
        snap.alt_block_bodies(&row_id).expect_err("not its bodies"),
        "alt_block_bodies"
    ));
    drop(snap);
    // Bodies without a row:
    let stray = BlockHash::from_bytes([0x5B; 32]);
    plant_bodies(&store, stray, &AltBodies::of(Vec::new()));
    let snap = store.begin_read().expect("read");
    assert!(is_si7(
        snap.alt_block_bodies(&stray).expect_err("no row"),
        "alt_blocks"
    ));
    cleanup(&path);
}

#[test]
fn insert_of_a_held_hash_and_remove_of_an_absent_one_are_refusals() {
    let path = tmp("alt-refusals");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![]]).hashes;
    let a = side_candidate(h(1), main[0], 5).block.hash();

    insert_admitted(&store, side_candidate(h(1), main[0], 5)).expect("first insert");

    // The same block, admitted again: the tier judges it the same way (it
    // reads the chain, not the alt table's membership), and the store
    // refuses the second row. K3's belt is the store's, not the tier's.
    let out = insert_admitted(&store, side_candidate(h(1), main[0], 5));
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
    plant_bytes(&store, bad, forged::<AltBlock>(&[0xFF; 9]));

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

    // Poison aborts the batch. No connect, pop, or chain_view ran, so no
    // height is noted and the writer stays live: an alt row is not chain
    // work, and a side-table decode failure must not stop main-chain connects.
    let out: Result<(), TestErr> = store.write(|batch| {
        let e = batch.alt_block(&bad).expect_err("corrupt");
        assert!(is_si7(&e));
        Ok(())
    });
    assert!(out.is_err(), "the poisoned batch refuses to commit");
    assert!(
        store.connect_state().is_live(),
        "alt corruption aborts the batch and does not halt the writer"
    );
    cleanup(&path);
}

/// A well-formed row planted under a key that is not the block's hash.
/// AL1 cannot write this — it keys the row by its verdict's hash (CEN-B6)
/// — so a row that reached the file this way came around that boundary,
/// and is SI-7 on AL4 and AL7, the same belt `block_body` applies to
/// `blocks` against `block_info.hash`. AL5 does not decode, so membership
/// still answers.
#[test]
fn a_row_whose_block_does_not_hash_to_its_key_is_si7() {
    let path = tmp("alt-key-mismatch");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![]]).hashes;
    let (a, a_bytes) = side_block(h(1), main[0], 7);
    let wrong = BlockHash::from_bytes([0xBD; 32]);
    assert_ne!(wrong, a);
    plant(&store, wrong, &alt(h(1), &a_bytes, None));

    let is_mismatch = |e: &StoreError| {
        matches!(
            e,
            StoreError::InvariantViolated(StoreInvariant::CellCorrupt {
                key: "alt_blocks",
                fault: CellFault::Undecodable(CodecError::Invalid {
                    codec: "alt_block",
                    reason,
                }),
            }) if *reason == super::alt_reads::ALT_KEY_MISMATCH
        )
    };
    let snap = store.begin_read().expect("read");
    assert!(is_mismatch(&snap.alt_block(&wrong).expect_err("mismatch")));
    assert!(is_mismatch(&snap.alt_blocks().expect_err("mismatch")));
    assert!(
        snap.has_alt_block(&wrong).expect("has"),
        "membership does not decode"
    );
    assert!(
        store.connect_state().is_live(),
        "a snapshot read arms nothing"
    );
    drop(snap);

    let out: Result<(), TestErr> = store.write(|batch| {
        let e = batch.alt_block(&wrong).expect_err("mismatch");
        assert!(is_mismatch(&e));
        Ok(())
    });
    assert!(out.is_err(), "the poisoned batch refuses to commit");
    assert!(
        store.connect_state().is_live(),
        "a mis-keyed alt row does not halt the writer"
    );
    cleanup(&path);
}

/// SAL-1: pop to the split, demote, promote, remove — one closure. Then the
/// same closure failing at its last step, and nothing of it landed.
#[test]
fn a_switch_is_one_transaction_or_none_of_it() {
    let path = tmp("alt-switch");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    // Main chain: the spendable prefix, a coinbase-only block `s`, and a
    // spend block `top` on it. A competing block `top'` on `s` is held as
    // an alt. At `top` two coinbases have matured (blocks 0 and 1's,
    // `height_maturing(2) = top`): the main top spends block 0's, its
    // competitor block 1's — two spends, two bodies, one parent.
    let s = FIRST_SPEND_HEIGHT;
    let top = s + 1;
    let mut grown = connect_chain(&store, &spendable_prefix(vec![Vec::new()]));
    let main = grown.hashes.clone();
    // Both spends are built for `top` over the chain through `s`. The
    // competitor's is built first and named, so the main top's `spend()`
    // takes the other matured coinbase.
    let alt_spend = grown.spend_of(1, 0);
    let main_cand = grown.next(&store, &[spend()]);
    let main_txs = main_cand.transactions.clone();
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        batch.connect(judge(&view, main_cand)?, RuleSet::GENESIS)?;
        Ok(())
    });
    out.expect("the main top connects");
    // The main top's bytes **as connected** — its coinbase priced by the
    // connect (CEN-F18), so the demoted block's bytes are the recorded ones.
    let main_top = {
        let snap = store.begin_read().expect("read");
        match snap.block(BlockHeight::from_raw(top)).expect("block") {
            shekyl_chain_rules::AtHeight::Recorded(body) => body.block,
            shekyl_chain_rules::AtHeight::AboveTip => panic!("top is connected"),
        }
    };
    let main_top_hash = main_top.hash();
    let main_top_bytes = main_top.serialize();
    // The competitor is priced by construction: it shares the main top's
    // parent state (the accumulator, the burned fold, the windows, the leaf
    // count at `top`) and its one listed body has the main top's weight and
    // fee (one input, two outputs, no fee: the same shape of spend), so F18
    // owes both coinbases the same amount — the connected block's, written
    // here with the wallet's `repay` as the pricer writes it. Its identity
    // is needed before the switch (it is held as an alt), so it cannot
    // wait for the batch that prices it.
    let mut alt_cand = candidate_over(
        root_going_into(&store, top),
        top,
        main[at(BlockHeight::from_raw(s))],
        vec![alt_spend],
    );
    let main_top_pays = fixture::paid(&main_top.miner_transaction)
        .expect("the connected coinbase is one the wallet reads")
        .amount;
    assert!(
        repay(
            &mut alt_cand.block.miner_transaction,
            MinerWallet::harness().recipient(),
            main_top_pays,
        ),
        "the fixture's coinbase is one `repay` prices"
    );
    let alt_top = alt_cand.block.hash();
    let alt_witness = vec![0x5A; 40];
    // top' through the tier, carrying its witness (CW-2): the alt row is
    // the verdict. Its parent is recorded, so the chain has no entries and
    // the fork pops one block.
    // The snapshot stays live through the write: the verdict borrows it.
    let judged = store.begin_read().expect("read");
    let alt_valid = admitted(&judged, with_witness(alt_cand.clone(), &alt_witness));
    assert_eq!(alt_valid.hash(), alt_top);
    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.insert_alt_block(alt_valid)?));
    out.expect("hold top'");
    drop(judged);

    // The demoted block, judged by the tier over the snapshot the switch
    // reads — before the pop (SAL-13), as the sketch in `store::alt` has
    // it; whether the switch re-enters demotions this way is a5's
    // (`DRS_E5_POOL_ALT_PRUNE.md` §5). The bytes are the recorded ones.
    let judged = store.begin_read().expect("read");
    let demoted = admitted(&judged, Candidate::new(main_top.clone(), main_txs.clone()));
    assert_eq!(demoted.hash(), main_top_hash);

    // The switch to top': demote top, promote top'.
    let out: Result<Vec<u8>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        // Read what the switch is about to change, through the batch.
        let promoted = batch.alt_block(&alt_top)?.expect("top' is held");
        let popped = batch.pop()?;
        assert_eq!(popped.height, BlockHeight::from_raw(top));
        batch.insert_alt_block(demoted)?;
        batch.connect(judge(&view, alt_cand.clone())?, RuleSet::GENESIS)?;
        batch.remove_alt_block(&alt_top)?;
        Ok(promoted.attestation_witness().expect("witness").to_vec())
    });
    assert_eq!(
        out,
        Ok(alt_witness),
        "the promoted block's witness travels out of the switch"
    );
    assert_eq!(tip_height(&store), Some(top));
    assert_eq!(hash_at(&store, top), Some(alt_top));
    {
        let snap = store.begin_read().expect("read");
        let held = snap
            .alt_block(&main_top_hash)
            .expect("get")
            .expect("the demoted block is an alt block");
        assert_eq!(
            held.block().serialize(),
            main_top_bytes,
            "demoted as recorded: the priced coinbase, not the fixture's"
        );
        assert!(
            !snap.has_alt_block(&alt_top).expect("has"),
            "the promoted block is not"
        );
        assert_eq!(snap.alt_block_count().expect("len"), 1);
    }
    drop(judged);

    // The same switch back, failing at its last step: nothing landed. top'
    // is judged over the pre-switch snapshot again (it is the tip there;
    // the tier reads the chain its parent is on, not the alt table).
    let judged = store.begin_read().expect("read");
    let re_demoted = admitted(&judged, alt_cand.clone());
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        batch.pop()?;
        batch.insert_alt_block(re_demoted)?;
        // The main top, re-promoted: the block as recorded and the body it
        // listed (pricing the priced coinbase again writes the same amount).
        batch.connect(
            judge(&view, Candidate::new(main_top.clone(), main_txs.clone()))?,
            RuleSet::GENESIS,
        )?;
        batch.remove_alt_block(&main_top_hash)?;
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
    assert_eq!(tip_height(&store), Some(top));
    assert_eq!(hash_at(&store, top), Some(alt_top), "the pop did not land");
    let snap = store.begin_read().expect("read");
    assert!(
        snap.has_alt_block(&main_top_hash).expect("has"),
        "the remove did not land"
    );
    assert!(
        !snap.has_alt_block(&alt_top).expect("has"),
        "the insert did not land"
    );
    assert!(store.connect_state().is_live(), "a refusal is not a halt");
    cleanup(&path);
}

/// SAL-15: the alt surface is *not chain state* (§11.2) — a fact every
/// digest declared and, for `alt_blocks` and its witness, nothing enforced
/// (`LMDB_WRITE_ATOMICITY_AUDIT.md`, non-canonical class: "declared, not
/// enforced"). With the witness a field of the alt row there is one table
/// to test: an AL1 carrying a witness must move no digest. This test exists
/// because the fold made the boundary testable, not because the fold was
/// made to close the audit row.
#[test]
fn an_alt_block_with_a_witness_moves_no_digest() {
    let path = tmp("alt-digest-boundary");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &spendable_prefix(vec![vec![spend()]])).hashes;
    let before = store
        .begin_read()
        .expect("read")
        .logical_state_digest_v0()
        .expect("digest");

    let judged = store.begin_read().expect("read");
    let a_valid = admitted(
        &judged,
        with_witness(side_candidate(h(1), main[0], 6), &[0xC3; 40]),
    );
    let a = a_valid.hash();
    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.insert_alt_block(a_valid)?));
    out.expect("insert");
    drop(judged);
    let snap = store.begin_read().expect("read");
    assert!(snap.has_alt_block(&a).expect("has"), "the write landed");
    assert_eq!(
        snap.logical_state_digest_v0().expect("digest"),
        before,
        "an alt block and its witness are outside the digest's domain"
    );

    // And the removal moves nothing either — the boundary holds in both
    // directions, as the pool's did.
    drop(snap);
    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.remove_alt_block(&a)?));
    out.expect("remove");
    assert_eq!(
        store
            .begin_read()
            .expect("read")
            .logical_state_digest_v0()
            .expect("digest"),
        before
    );
    cleanup(&path);
}
