// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! DRS-E5 slice 9 a3: [`AltChain::build`] holds CEN-K2 (the orphan is a
//! refusal; a chain through two alt entries reaches a recorded row), the
//! stitched [`AltView`] answers `BatchView`'s reads below the fork point and
//! the alt entries' above it, and CEN-K1a holds by construction — no build
//! yields a candidate at height zero. A row whose recorded height disagrees
//! with its chain is SI-7, the assertion the C++ rebuild made.
//!
//! Rows the tier would have written go through it (`alt_tests::admitted`
//! then AL1); rows the tier would never write — an orphan's, a row whose
//! height disagrees with its chain — are planted (`alt_tests::plant`),
//! because that is the only way they reach a file.

use shekyl_chain_rules::{AtHeight, Candidate, Fork, HeaderRecord, HeaderView, Tip};
use shekyl_types::{BlockHash, BlockHeight};

use super::alt_tests::{admitted, alt, h, plant, side_block, side_candidate, with_witness};
use super::connect_fixtures::connect_chain;
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::*;

/// `BatchView::header_at(h)` — the main-chain read the stitched view must
/// agree with below the fork point.
fn recorded_header(store: &ChainStore, height: BlockHeight) -> AtHeight<HeaderRecord> {
    let out: Result<AtHeight<HeaderRecord>, TestErr> =
        store.write(|batch| Ok(batch.chain_view().header_at(height)?));
    out.expect("recorded header")
}

fn recorded(at: AtHeight<HeaderRecord>) -> HeaderRecord {
    match at {
        AtHeight::Recorded(record) => record,
        AtHeight::AboveTip => panic!("expected a recorded header"),
    }
}

/// Through the tier and AL1; the row's key.
fn admit(store: &ChainStore, candidate: Candidate) -> BlockHash {
    let snap = store.begin_read().expect("read");
    let valid = admitted(&snap, candidate);
    let id = valid.hash();
    let out: Result<(), TestErr> = store.write(|batch| Ok(batch.insert_alt_block(valid)?));
    out.expect("insert alt");
    id
}

#[test]
fn the_orphan_is_unlinked_at_the_first_unheld_hash() {
    // CEN-K2's refusal. A parent nobody holds; then a two-entry chain whose
    // first entry links to a hash nobody holds — the refusal names that
    // hash, not the parent the caller asked about. The tier refuses an
    // orphan before AL1 is reached (`admitted` would panic here), so the
    // two rows are planted: this is what a file holds if something wrote
    // around AL1, and the walk still finds the gap.
    let path = tmp("alt-view-orphan");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![], vec![]]).hashes;
    let unknown = BlockHash::from_bytes([0x0F; 32]);
    let (a, a_bytes) = side_block(h(1), unknown, 3);
    let (b, b_bytes) = side_block(h(2), a, 4);
    plant(&store, a, &alt(h(1), &a_bytes, None));
    plant(&store, b, &alt(h(2), &b_bytes, None));

    let snap = store.begin_read().expect("read");
    let unlinked = |at: BlockHash| StoreError::from(AltCannot::Unlinked { at }).to_string();
    assert_eq!(
        AltChain::build(&snap, &unknown)
            .expect_err("orphan")
            .to_string(),
        unlinked(unknown)
    );
    assert_eq!(
        AltChain::build(&snap, &b).expect_err("orphan").to_string(),
        unlinked(unknown),
        "the walk went b → a → unknown and names where it stopped"
    );
    assert_eq!(
        StoreError::from(AltCannot::Unlinked { at: unknown }).class(),
        ErrorClass::Cannot,
        "the orphan is a decision, not a fault"
    );
    assert!(
        store.connect_state().is_live(),
        "a refused build arms nothing"
    );
    drop(snap);

    // An empty store holds nothing: every parent is the orphan (K2), found
    // before any walk — there is no recorded tip to fork from — and no
    // height is ever derived (K1a has no case here).
    let empty_path = tmp("alt-view-empty");
    let empty = ChainStore::create(&empty_path, EPOCH).expect("create");
    let snap = empty.begin_read().expect("read");
    assert_eq!(
        AltChain::build(&snap, &main[0])
            .expect_err("nothing recorded")
            .to_string(),
        unlinked(main[0])
    );
    drop(snap);
    drop(empty);
    cleanup(&empty_path);
    drop(store);
    cleanup(&path);
}

#[test]
fn a_chain_through_two_alt_entries_reaches_a_recorded_row() {
    // CEN-K2 held; CEN-K1a by construction on every chain built here: the
    // candidate's height is `root + 1 + len`, and the root is recorded.
    let path = tmp("alt-view-chain");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![], vec![], vec![]]).hashes;
    let a = admit(&store, side_candidate(h(1), main[0], 3));
    let b = admit(&store, side_candidate(h(2), a, 4));

    let snap = store.begin_read().expect("read");
    let at = |h: u64, hash: BlockHash| Tip {
        height: BlockHeight::from_raw(h),
        hash,
    };

    let over_b = AltChain::build(&snap, &b).expect("links");
    assert_eq!(over_b.root(), at(0, main[0]));
    assert_eq!(
        over_b.entries().iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![a, b],
        "ascending from the fork point"
    );
    assert_eq!(over_b.parent(), at(2, b));
    assert_eq!(over_b.candidate_height(), BlockHeight::from_raw(3));
    assert_eq!(
        over_b.fork(),
        Fork::new(at(0, main[0]), at(2, main[2])).expect("root is not above the tip"),
        "the fork names the root and the recorded tip of the one snapshot"
    );

    let over_a = AltChain::build(&snap, &a).expect("links");
    assert_eq!(over_a.root(), at(0, main[0]));
    assert_eq!(over_a.entries().len(), 1);
    assert_eq!(over_a.candidate_height(), BlockHeight::from_raw(2));

    // A recorded parent: the chain is the fork point alone.
    let over_main = AltChain::build(&snap, &main[1]).expect("links");
    assert_eq!(over_main.root(), at(1, main[1]));
    assert!(over_main.entries().is_empty());
    assert_eq!(over_main.parent(), at(1, main[1]));
    assert_eq!(over_main.candidate_height(), BlockHeight::from_raw(2));
    assert_eq!(over_main.fork().root(), at(1, main[1]));
    assert_eq!(over_main.fork().recorded_tip(), at(2, main[2]));

    // K1a: the lowest root is genesis, and a candidate over it sits at 1.
    // There is no chain whose candidate height is 0 — the falsifier is a
    // build that returns one.
    let over_genesis = AltChain::build(&snap, &main[0]).expect("links");
    assert_eq!(over_genesis.candidate_height(), BlockHeight::from_raw(1));
    for chain in [&over_b, &over_a, &over_main, &over_genesis] {
        assert!(
            chain.candidate_height() >= BlockHeight::from_raw(1),
            "CEN-K1a: {chain:?}"
        );
    }
    drop(snap);
    drop(store);
    cleanup(&path);
}

#[test]
fn the_alt_view_is_the_recorded_chain_below_the_fork_and_the_entries_above() {
    // The stitched-view conformance test. Below the fork point the view
    // answers exactly what `BatchView::header_at` answers — one read body;
    // above it, the alt entries' hash, header and cumulative difficulty;
    // above the parent, `AboveTip`. The recorded chain above the fork point
    // is not visible: `main[2]` and `a` are two answers to height 2, and
    // the view gives the one it is judging.
    let path = tmp("alt-view-stitched");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![], vec![], vec![], vec![]]).hashes;
    let a = admit(&store, side_candidate(h(2), main[1], 3));
    let b = admit(&store, with_witness(side_candidate(h(3), a, 4), &[0xA5; 8]));

    let snap = store.begin_read().expect("read");
    // The rows as the tier wrote them: what the stitched view must answer
    // above the fork point.
    let a_row = snap.alt_block(&a).expect("get").expect("held");
    let b_row = snap.alt_block(&b).expect("get").expect("held");
    assert_eq!(b_row.attestation_witness(), Some(&[0xA5; 8][..]));
    let chain = AltChain::build(&snap, &b).expect("links");
    let view = AltView::new(&snap, chain);

    // Below and at the fork point: the recorded rows, as `BatchView` reads them.
    for height in 0..=1u64 {
        let stitched = recorded(view.header_at(h(height)).expect("read"));
        assert_eq!(stitched, recorded(recorded_header(&store, h(height))));
        assert_eq!(stitched.hash, main[usize::try_from(height).expect("small")]);
    }

    // Above it: the entries.
    let at_two = recorded(view.header_at(h(2)).expect("read"));
    assert_eq!(at_two.hash, a);
    assert_eq!(at_two.header, a_row.block().header);
    assert_eq!(at_two.cumulative_difficulty, a_row.cumulative_difficulty());
    assert_ne!(
        at_two.hash, main[2],
        "the recorded block at the fork height is not what the alt tier reads"
    );
    assert_eq!(
        recorded(recorded_header(&store, h(2))).hash,
        main[2],
        "negative control: the recorded reader still answers main[2] there"
    );
    let at_three = recorded(view.header_at(h(3)).expect("read"));
    assert_eq!(at_three.hash, b);
    assert_eq!(at_three.header, b_row.block().header);
    assert_eq!(
        at_three.cumulative_difficulty,
        b_row.cumulative_difficulty()
    );

    // The parent is the tip; above it is absence, though the recorded chain
    // runs to 3 and beyond the view's root the recorded 2 and 3 exist.
    assert_eq!(
        view.tip().expect("tip"),
        Some(Tip {
            height: h(3),
            hash: b
        })
    );
    assert_eq!(view.header_at(h(4)).expect("read"), AtHeight::AboveTip);
    assert_eq!(
        view.header_at(h(u64::MAX)).expect("read"),
        AtHeight::AboveTip
    );
    assert_eq!(view.chain().entries().len(), 2);

    // A zero-entry chain: the view is the recorded chain truncated at the
    // parent. Height 2 is recorded on the main chain and absent here.
    let truncated = AltView::new(&snap, AltChain::build(&snap, &main[1]).expect("links"));
    assert_eq!(
        recorded(truncated.header_at(h(1)).expect("read")),
        recorded(recorded_header(&store, h(1)))
    );
    assert_eq!(truncated.header_at(h(2)).expect("read"), AtHeight::AboveTip);
    assert_eq!(
        truncated.tip().expect("tip"),
        Some(Tip {
            height: h(1),
            hash: main[1]
        })
    );
    assert!(
        store.connect_state().is_live(),
        "snapshot reads arm nothing"
    );
    drop(snap);
    drop(store);
    cleanup(&path);
}

#[test]
fn a_row_whose_height_disagrees_with_its_chain_is_si7() {
    // The C++ asserted linkage "at the claimed height" while rebuilding
    // (CEN-K2's row). A row that links to genesis and claims height 5 is
    // not a chain anyone can be judged against; it is the store's own
    // bookkeeping disagreeing with itself — SI-7, not a refusal. AL1 cannot
    // write it (the verdict's height is derived over the chain), so the
    // rows are planted.
    let path = tmp("alt-view-height");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let main = connect_chain(&store, &[vec![], vec![]]).hashes;
    let (a, a_bytes) = side_block(h(5), main[0], 3);
    plant(&store, a, &alt(h(5), &a_bytes, None));
    let (b, b_bytes) = side_block(h(6), a, 4);
    plant(&store, b, &alt(h(6), &b_bytes, None));

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
    let e = AltChain::build(&snap, &a).expect_err("height 5 over genesis");
    assert!(is_si7(&e), "{e}");
    assert!(e.to_string().contains("recorded height disagrees"), "{e}");
    // The disagreement is found wherever it sits on the walk.
    let e = AltChain::build(&snap, &b).expect_err("b's chain carries it");
    assert!(is_si7(&e), "{e}");
    assert!(
        store.connect_state().is_live(),
        "a snapshot read arms nothing"
    );
    drop(snap);
    drop(store);
    cleanup(&path);
}
