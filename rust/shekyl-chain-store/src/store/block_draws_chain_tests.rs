// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The count against the slash harness's chain (`SO-D12` increment 3).
//!
//! A child of `drawable_walk_tests`. Epoch 2 holds four pairs, nothing is
//! admitted, and the stored rows are the production composition. A warm
//! memo, a miss, a switch, an aborted switch, a drifted journal (SI-30)
//! and a removed digest (SI-29) run on the chain the drawable-set tests build.

use shekyl_archival_retention::{draw_count, draw_horizon, BundleKept, DrawablePair, PassBitmap};
use shekyl_chain_rules::{
    issued_draw_term, Admitted, BlockDrawsFloor, ChainView as _, DerivedDraw, DrawableMemo,
    EpochFloor, ReleaseJournalFloor, Settling,
};
use shekyl_harness_spender::Persona;
use shekyl_types::archival::{BlockDraws, IssuedDigest, COUNTED_DRAWS};
use shekyl_types::{BlockHeight, SettlementEpoch, ShardId};

use crate::codec::{BondRecord, Canonical};

use super::super::super::{Popped, StoreError, StoreInvariant, WriteBatch};
use super::super::{Listed, SlashedChain, TestErr, RULES, WITNESS_PERSONAS};
use super::{h_open, no_draws, BONDED, FIRST};

/// The count against a store chain whose epoch 2 holds four pairs.
///
/// The chain is the harness's through `h_open(2) − 1`, then eleven blocks
/// into the epoch. `|D|` is 4, nothing is admitted, and the rows are the
/// production composition (`draw_horizon`, `draw_count`, the in-flight sum)
/// with three blocks pinned by hand. A warm memo, an empty memo mid-epoch,
/// a fresh replay, the next epoch and an aborted open write the same rows.
/// A memo that saw the other fork's open, then a switch onto a release at
/// the open, writes the winning chain's rows. A journal row changed after
/// the open, and a removed digest, halt the next block. An aborted switch
/// that then continues on the chain that stayed is
/// [`an_aborted_switch_does_not_change_the_next_row`]: the abort and the
/// switch here both continue on the set inserted last.
#[test]
fn the_count_on_a_non_empty_set_matches_the_composition_and_ignores_the_memo() {
    let open = h_open(2);
    let last = open + 11;
    let mut chain = SlashedChain::build_with("count-set", WITNESS_PERSONAS, open - 1, no_draws);
    assert_eq!(
        draws_of(&chain, BlockHeight::from_raw(open - 1)),
        BlockDraws::ZERO,
        "epoch 1's set is empty, so the block before the open is a zero row"
    );

    let reference = {
        let mut cold = None;
        connect_span(&mut chain, open, last, &mut cold)
    };
    let composed = compose(4, open, last);
    assert_eq!(
        reference, composed,
        "the stored rows are the production composition"
    );
    assert_eq!(
        reference[0],
        BlockDraws {
            count: 0,
            carry: 429_496_729,
            shortfall: 12,
            issued_short: 0,
            revealed: false,
        },
        "h_open: H = 200, u = 12, t = 2^32 / 10"
    );
    assert_eq!(
        reference[10],
        BlockDraws {
            count: 1,
            carry: 429_496_723,
            shortfall: 12,
            issued_short: 0,
            revealed: false,
        },
        "the eleventh block of the epoch carries the count across 2^32"
    );
    assert_eq!(
        reference[11],
        BlockDraws {
            count: 0,
            carry: 837_518_616,
            shortfall: 12,
            issued_short: 0,
            revealed: false,
        },
        "the next block's in-flight sum includes that one draw"
    );

    pop_back(&mut chain, last - open + 1);
    let mut warm = DrawableMemo::new();
    let again = connect_span(&mut chain, open, last, &mut Some(&mut warm));
    assert_eq!(again, reference, "a memo and no memo write the same rows");

    // The memo filled at the open, so the blocks after it hit. Drop it
    // and continue: the next block misses, rebuilds, and matches the digest.
    pop_back(&mut chain, 4);
    let mut restarted = DrawableMemo::new();
    let tail = connect_span(&mut chain, last - 3, last, &mut Some(&mut restarted));
    assert_eq!(
        tail.as_slice(),
        &reference[reference.len() - 4..],
        "an empty memo mid-epoch rebuilds and writes the same rows"
    );

    pop_back(&mut chain, last - open + 1);
    let mut cold = None;
    let replay = connect_span(&mut chain, open, last, &mut cold);
    assert_eq!(replay, reference, "a fresh replay writes the same rows");

    pop_back(&mut chain, last - open + 1);
    let mut aborted = DrawableMemo::new();
    let txs = chain.grown.realise(&[]);
    let abandoned: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let _ = chain
            .grown
            .judge_listing_with_memo(&view, &RULES, &txs, Some(&mut aborted))?;
        Err(TestErr::Abort)
    });
    assert!(matches!(abandoned, Err(TestErr::Abort)));
    chain.grown.pop();
    let after_abort = connect_span(&mut chain, open, open + 1, &mut Some(&mut aborted));
    assert_eq!(
        after_abort,
        reference[..2],
        "an aborted open leaves the next committed rows unchanged"
    );

    // The other fork opens the epoch with no release (`|D| = 4`). Pop it,
    // keeping the memo, and adopt the release (`|D| = 3`).
    pop_back(&mut chain, 2);
    let mut switched = DrawableMemo::new();
    connect_listed(&mut chain, &[], Some(&mut switched));
    pop_back(&mut chain, 1);
    let release = [Listed::Release {
        slot: FIRST,
        bonded_total: BONDED,
    }];
    let won = [
        connect_listed(&mut chain, &release, Some(&mut switched)),
        connect_listed(&mut chain, &[], Some(&mut switched)),
    ];
    pop_back(&mut chain, 2);
    let cold = [
        connect_listed(&mut chain, &release, None),
        connect_listed(&mut chain, &[], None),
    ];
    assert_eq!(
        won, cold,
        "a warm memo through the switch matches a cold chain"
    );
    assert_ne!(
        won[0].shortfall, reference[0].shortfall,
        "the release at the open is a different set from the chain the memo saw first"
    );
    pop_back(&mut chain, 2);
    let mut fresh = DrawableMemo::new();
    let replayed = [
        connect_listed(&mut chain, &release, Some(&mut fresh)),
        connect_listed(&mut chain, &[], Some(&mut fresh)),
    ];
    assert_eq!(
        replayed, cold,
        "a fresh replay of the winning chain matches"
    );

    // The release sits above the open, so epoch 2's digest does not include
    // it. Changing the journal is drift (SI-30). A missing digest is the
    // digest's own row (SI-29), not drift.
    pop_back(&mut chain, 2);
    connect_listed(&mut chain, &[], None);
    connect_listed(&mut chain, &release, None);
    let epoch = SettlementEpoch::from_raw(2);
    let drift: Result<(), TestErr> = chain.store.write(|batch| {
        let mut record = journaled(batch)?;
        record.holdings =
            shekyl_types::archival::Holdings::shard_set(Vec::new()).expect("the empty set");
        rewrite_journal(batch, &record)?;
        let view = batch.chain_view();
        let Err(corrupt) = chain.grown.judge_empty_or_corrupt(&view, &RULES)? else {
            panic!("the count rebuilt a set the open did not digest");
        };
        assert_eq!(
            corrupt,
            shekyl_chain_rules::Corrupt::SettlementIntegrity {
                epoch,
                check: shekyl_chain_rules::SettlementCheck::DrawableDrift,
            }
        );
        Err(batch.refuse_corrupt(corrupt).into())
    });
    let TestErr::Store(refused) = drift.expect_err("drift refuses") else {
        panic!("aborted, not refused");
    };
    assert!(
        refused.contains("does not digest to archival_drawable_digest"),
        "{refused}"
    );

    let far = h_open(3) + 2;
    assert_eq!(
        rows_from_open("count-memo", far, true),
        rows_from_open("count-none", far, false),
        "a memo and no memo write the same rows across the next open"
    );

    let chain = SlashedChain::build_with("count-digest", WITNESS_PERSONAS, open, no_draws);
    let missing: Result<(), TestErr> = chain.store.write(|batch| {
        batch
            .open_remove_table(
                crate::schema::ARCHIVAL_DRAWABLE_DIGEST,
                StoreInvariant::TipMismatch,
            )?
            .remove(2)?;
        let view = batch.chain_view();
        let Err(corrupt) = chain.grown.judge_empty_or_corrupt(&view, &RULES)? else {
            panic!("the count ran without epoch 2's digest");
        };
        assert_eq!(
            corrupt,
            shekyl_chain_rules::Corrupt::SettlementIntegrity {
                epoch,
                check: shekyl_chain_rules::SettlementCheck::DrawableDigestMissing,
            }
        );
        Err(batch.refuse_corrupt(corrupt).into())
    });
    let TestErr::Store(refused) = missing.expect_err("a missing digest refuses") else {
        panic!("aborted, not refused");
    };
    assert!(refused.contains("holds no digest"), "{refused}");
    chain.finish();
}

/// An aborted switch inserts the other fork's set and does not adopt it.
///
/// Chain A is connected through `h_open(2) + 1` with a memo, so the memo
/// holds A's opening set (`|D| = 4`). One batch then pops below A's open
/// and connects fork B's open with the release (`|D| = 3`); the batch is
/// aborted. The store stays on A. The memo keeps B's set under B's opening
/// hash, because a memo is not undone. A's next block asks for A's hash,
/// and its row is the reference row for that height.
///
/// [`the_count_on_a_non_empty_set_matches_the_composition_and_ignores_the_memo`]'s
/// abort reconnects A's own open, and its switch continues on the winner.
/// Both next blocks ask for the set that was inserted last, so both still
/// pass when [`DrawableMemo::get`] matches the epoch and ignores the hash.
/// This block asks for the set that was inserted first. Red edit: return
/// the epoch's latest set from `get`.
#[test]
fn an_aborted_switch_does_not_change_the_next_row() {
    let open = h_open(2);
    let mut chain =
        SlashedChain::build_with("count-abort-switch", WITNESS_PERSONAS, open - 1, no_draws);
    let reference = compose(4, open, open + 2);
    let mut memo = DrawableMemo::new();
    let committed = connect_span(&mut chain, open, open + 1, &mut Some(&mut memo));
    assert_eq!(
        committed.as_slice(),
        &reference[..2],
        "A through h_open + 1 is the reference chain"
    );
    let kept_open = chain.grown.block(BlockHeight::from_raw(open)).clone();
    let kept_next = chain.grown.block(BlockHeight::from_raw(open + 1)).clone();

    let abandoned: Result<(), TestErr> = chain.store.write(|batch| {
        batch.pop()?;
        batch.pop()?;
        chain.grown.pop();
        chain.grown.pop();
        let release = [Listed::Release {
            slot: FIRST,
            bonded_total: BONDED,
        }];
        let txs = chain.grown.realise(&release);
        let view = batch.chain_view();
        let judged = chain
            .grown
            .judge_listing_with_memo(&view, &RULES, &txs, Some(&mut memo))?;
        batch.connect(judged, RULES)?;
        Err(TestErr::Abort)
    });
    assert!(
        matches!(abandoned, Err(TestErr::Abort)),
        "the switch batch aborted, found {abandoned:?}"
    );
    // The store rolled back to A. `grown` followed the batch, so put A's
    // two blocks back before the next connect.
    chain.grown.pop();
    chain.grown.record(&kept_open, &[]);
    chain.grown.record(&kept_next, &[]);
    assert_eq!(
        draws_of(&chain, BlockHeight::from_raw(open + 1)),
        reference[1],
        "the aborted batch did not adopt B"
    );

    let next = connect_listed(&mut chain, &[], Some(&mut memo));
    assert_eq!(
        next, reference[2],
        "A's next block counts A's set, not the set the aborted fork inserted"
    );
    chain.finish();
}

/// Epoch 2's open through `through`, on a chain of its own. `with_memo`
/// carries one memo from the open; otherwise every block rebuilds.
fn rows_from_open(label: &str, through: u64, with_memo: bool) -> Vec<BlockDraws> {
    let open = h_open(2);
    let mut chain = SlashedChain::build_with(label, WITNESS_PERSONAS, open - 1, no_draws);
    let mut memo = DrawableMemo::new();
    let mut slot = if with_memo { Some(&mut memo) } else { None };
    let rows = connect_span(&mut chain, open, through, &mut slot);
    chain.finish();
    rows
}

fn draws_of(chain: &SlashedChain, height: BlockHeight) -> BlockDraws {
    chain
        .store
        .begin_read()
        .expect("read")
        .block_draws(height, BlockDrawsFloor::NONE)
        .expect("read")
        .expect("the row was written")
}

fn connect_listed(
    chain: &mut SlashedChain,
    listed: &[Listed],
    memo: Option<&mut DrawableMemo>,
) -> BlockDraws {
    let txs = chain.grown.realise(listed);
    let mut found = None;
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = chain
            .grown
            .judge_listing_with_memo(&view, &RULES, &txs, memo)?;
        found = Some(judged.block().archival().draws());
        batch.connect(judged, RULES)?;
        Ok(())
    });
    out.expect("the block connects");
    found.expect("the verdict carries the row")
}

fn connect_span(
    chain: &mut SlashedChain,
    from: u64,
    through: u64,
    memo: &mut Option<&mut DrawableMemo>,
) -> Vec<BlockDraws> {
    let mut rows = Vec::new();
    for _ in from..=through {
        rows.push(connect_listed(chain, &[], memo.as_deref_mut()));
    }
    rows
}

fn pop_back(chain: &mut SlashedChain, n: u64) {
    for _ in 0..n {
        let popped: Result<Popped, TestErr> = chain.store.write(|batch| Ok(batch.pop()?));
        popped.expect("pop");
        chain.grown.pop();
    }
}

/// The production composition for an epoch that opens at `h_open` with
/// `set_size` pairs and admits nothing. The unsettled shortfall is
/// `max(0, visible − in flight)`, the same saturation [`draw_count`] is
/// specified to take.
fn compose(set_size: u64, h_open: u64, through: u64) -> Vec<BlockDraws> {
    let schedule = RULES.settlement_schedule();
    let seb = schedule.blocks().get();
    let window = schedule
        .challenge_response_blocks()
        .expect("the harness has a window")
        .get();
    let visible = u64::try_from(COUNTED_DRAWS).expect("three") * set_size;
    let mut rows: Vec<BlockDraws> = Vec::new();
    let mut carry = 0u32;
    for h in h_open..=through {
        let start = h.saturating_sub(window).max(h_open);
        let in_flight: u64 = rows
            .iter()
            .enumerate()
            .filter(|(i, row)| {
                let at = h_open + u64::try_from(*i).expect("fits");
                at >= start && at < h && !row.revealed
            })
            .map(|(_, row)| u64::from(row.count))
            .sum();
        let (count, next) = draw_count(
            set_size,
            visible.saturating_sub(in_flight),
            draw_horizon(h - h_open, seb, window),
            seb,
            carry,
        )
        .expect("the horizon fits");
        carry = next;
        rows.push(BlockDraws {
            count: u32::try_from(count).expect("the count fits"),
            carry: next,
            shortfall: visible,
            issued_short: 0,
            revealed: false,
        });
    }
    rows
}

/// A bundle for the last block of epoch 1, admitted at epoch 2's open.
/// Its index rows land in epoch 1. `issued_short` on the open stays zero,
/// so the next block keeps epoch 2's opening shortfall, 12 on this chain
/// (`COUNTED_DRAWS` times four pairs). The sim pins the same untouched
/// opening shortfall at 1536 when `|D|` is 512.
#[test]
fn a_late_admission_leaves_the_new_epochs_shortfall_untouched() {
    let open = h_open(2);
    let mut chain = SlashedChain::build_with("late-admit", WITNESS_PERSONAS, open - 1, no_draws);
    let admitted = late_bundle(open - 1);
    let memo = DrawableMemo::new();
    connect_admitting(&mut chain, &admitted, &memo);
    let prior = SettlementEpoch::from_raw(1);
    let floor =
        EpochFloor::<Settling>::under(BlockHeight::from_raw(open), RULES.settlement_schedule());
    let rows = chain
        .store
        .begin_read()
        .expect("read")
        .issued_draws(prior, floor)
        .expect("index");
    assert_eq!(rows.len(), 1, "the prior epoch's index gains the draw");
    assert_eq!(rows[0].issuing_height, BlockHeight::from_raw(open - 1));
    assert_eq!(rows[0].state.revealed_at, BlockHeight::from_raw(open));
    assert!(rows[0].state.passed);
    let mut digest = IssuedDigest::ZERO;
    digest.fold(&issued_draw_term(
        &rows[0].persona,
        rows[0].shard,
        prior,
        rows[0].issuing_height,
        rows[0].draw,
    ));
    assert_eq!(
        chain
            .store
            .begin_read()
            .expect("read")
            .issued_digest(prior, floor)
            .expect("digest"),
        digest
    );
    let opened = draws_of(&chain, BlockHeight::from_raw(open));
    assert_eq!(
        opened.issued_short, 0,
        "a prior-epoch bundle adds no reduction"
    );
    assert!(draws_of(&chain, BlockHeight::from_raw(open - 1)).revealed);

    pop_back(&mut chain, 1);
    assert!(
        chain
            .store
            .begin_read()
            .expect("read")
            .issued_draws(prior, floor)
            .expect("index")
            .is_empty(),
        "pop removes the index row with the block"
    );
    assert!(!draws_of(&chain, BlockHeight::from_raw(open - 1)).revealed);

    connect_admitting(&mut chain, &admitted, &memo);
    let next = connect_listed(&mut chain, &[], None);
    assert_eq!(opened.issued_short, 0);
    assert_eq!(
        opened.shortfall, 12,
        "epoch 2 opens at COUNTED_DRAWS times four pairs"
    );
    assert_eq!(next.shortfall, 12, "E + 1's shortfall is untouched");
    assert_eq!(
        u64::try_from(COUNTED_DRAWS).expect("three") * 512,
        1536,
        "the sim's |D| = 512 pins this same untouched opening shortfall"
    );
    chain.finish();
}

fn late_bundle(h: u64) -> Vec<Admitted> {
    let persona = Persona::at(0).id();
    vec![Admitted {
        kept: BundleKept {
            h: BlockHeight::from_raw(h),
            seed: [0x11; 32],
            passes: PassBitmap::from_passes(1, [0]).expect("one pass"),
        },
        draws: vec![DerivedDraw {
            index: 0,
            pair: DrawablePair {
                persona,
                shard: ShardId::from_raw(0),
            },
            passed: true,
        }],
    }]
}

fn connect_admitting(chain: &mut SlashedChain, admitted: &[Admitted], memo: &DrawableMemo) {
    let height = chain.grown.height();
    let txs = chain.grown.realise(&[]);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = chain
            .grown
            .judge_listing_with_memo(&view, &RULES, &txs, None)?;
        let bundle =
            super::super::StoreBundleView::new(&view, memo, height, RULES.settlement_schedule());
        batch.connect_admitting(judged, RULES, Some((&bundle, admitted)))?;
        Ok(())
    });
    out.expect("the block connects");
}

fn journaled(batch: &WriteBatch<'_, '_>) -> Result<BondRecord, StoreError> {
    let persona = Persona::at(FIRST).id();
    Ok(batch
        .chain_view()
        .release_journal_after(BlockHeight::from_raw(h_open(2)), ReleaseJournalFloor::NONE)?
        .into_iter()
        .find(|row| row.persona == persona)
        .expect("the release was journaled")
        .pre_image)
}

fn rewrite_journal(batch: &WriteBatch<'_, '_>, record: &BondRecord) -> Result<(), StoreError> {
    let key = crate::ids::ReleaseJournalKey::new(
        BlockHeight::from_raw(h_open(2) + 1),
        Persona::at(FIRST).id(),
    );
    batch
        .open_upsert_table(crate::schema::ARCHIVAL_RELEASE_JOURNAL)?
        .upsert(key.key(), record.encoded().as_encoded())?;
    Ok(())
}
