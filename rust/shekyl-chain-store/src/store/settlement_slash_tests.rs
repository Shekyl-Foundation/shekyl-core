// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Settlement wiring on the slash-scan chain: an empty issued-draw index,
//! the window's pass-over on a real connect, a digest that does not fold,
//! a popped deadline, and a second write of one row.
//!
//! The retention floor is specified on
//! `shekyl_archival_retention::settlement_window_slashable` (ruled
//! 2026-10-09). This file does not rebuild thirty epochs to re-derive it.
//! The harness these tests run is the parent module's.

use super::*;

/// With no draw issued, the slash pass settles nothing and slashes nothing
/// (`SO-D10a`): the state of every chain until the secret draw lands. The
/// witness's chain with an empty index, through three deadline connects.
#[test]
fn an_empty_index_settles_nothing_and_slashes_nothing() {
    fn nothing(_: u64, _: u64) -> Option<&'static [bool]> {
        None
    }
    let last = 2u64;
    let through = RULES.settlement_schedule().slash_deadline_height(last);
    let chain = SlashedChain::build_with("slash-empty-index", WITNESS_PERSONAS, through, nothing);
    let snap = chain.store.begin_read().expect("read");
    assert_eq!(
        snap.last_settled_slash_epoch().expect("read"),
        Some(SettlementEpoch::from_raw(last)),
        "the pass ran: the watermark moved"
    );
    assert_eq!(snap.total_burned().expect("read"), AtomicUnits::ZERO);
    for p in ids_in_table_order(chain.personas) {
        assert!(snap
            .slash_log_after(&p, BlockHeight::from_raw(0), slash_floor_at(&snap))
            .expect("read")
            .is_empty());
        assert!(snap
            .bond_record(&p)
            .expect("read")
            .expect("bonded")
            .is_complete_tree());
        for e in 0..=last {
            assert_eq!(
                snap.settlement_row(&p, ShardId::from_raw(0), SettlementEpoch::from_raw(e))
                    .expect("read"),
                None
            );
        }
    }
    drop(snap);
    chain.finish();
}

/// The window passes over an epoch that is not an observation and does
/// not stop at it (`SO-D10b`). Four pairs, one more epoch than the witness:
///
/// - persona 0 misses every epoch: slashed at epoch `M`, as the witness is.
/// - persona 1 is issued two draws in epoch 5, a NonObservation row. At `M`
///   it has `M − 1` misses and is not slashed. At `M + 1` it has `M`, with
///   epoch 5 passed over, and is. A walk that stopped at epoch 5 would
///   count the epochs above it only and never slash.
/// - persona 2 is issued nothing in epoch 5, so it has no row there. Same
///   verdict as persona 1: an absent row and a NonObservation row are one
///   case to the window.
/// - persona 3 is Served in epochs 3, 7 and 9. Three served epochs are
///   past the window's serve budget, so the walk ends at the third and
///   never gathers `m` misses: not slashed.
///
/// The chain runs one epoch past `M + 1` to show which draws count: a
/// pair is charged only for draws issued while it held the shard. Persona
/// 0's draws of `M + 2` were issued after its slash emptied the record, so
/// that epoch has no row for it; its draws of `M + 1` were issued before,
/// and do.
#[test]
fn the_window_passes_over_an_unobserved_epoch_and_counts_a_served_one() {
    fn plan(epoch: u64, persona: u64) -> Option<&'static [bool]> {
        match (persona, epoch) {
            (_, 0) | (2, 5) => None,
            (1, 5) => Some(SHORT),
            (3, 3 | 7 | 9) => Some(SERVED),
            _ => Some(MISSED),
        }
    }
    let m = u64::from(FAILURE_WINDOW_M);
    let schedule = RULES.settlement_schedule();
    let chain = SlashedChain::build_with(
        "slash-window-skip",
        4,
        schedule.slash_deadline_height(m + 2),
        plan,
    );
    let id = |i: u64| Persona::at(slot(i)).id();
    let shard = ShardId::from_raw(0);
    let epoch = SettlementEpoch::from_raw;
    let snap = chain.store.begin_read().expect("read");
    let slashed_at = |i: u64| -> Vec<u64> {
        (0..=m + 2)
            .filter(|e| snap.slash_applied(&id(i), shard, epoch(*e)).expect("read"))
            .collect()
    };
    assert_eq!(slashed_at(0), [m], "every epoch missed: slashed at M");
    assert_eq!(
        slashed_at(1),
        [m + 1],
        "a NonObservation epoch is passed over"
    );
    assert_eq!(
        slashed_at(2),
        [m + 1],
        "an epoch with no row is passed over"
    );
    assert_eq!(slashed_at(3), [0u64; 0], "three served epochs end the walk");

    // The rows the verdicts were read from.
    let outcome = |i: u64, e: u64| {
        snap.settlement_row(&id(i), shard, epoch(e))
            .expect("read")
            .map(SettlementRow::outcome)
    };
    assert_eq!(outcome(1, 5), Some(SettlementOutcome::NonObservation));
    assert_eq!(outcome(2, 5), None);
    assert_eq!(outcome(3, 3), Some(SettlementOutcome::Served));
    assert_eq!(outcome(3, 7), Some(SettlementOutcome::Served));
    assert_eq!(outcome(3, 9), Some(SettlementOutcome::Served));
    assert_eq!(outcome(3, 4), Some(SettlementOutcome::Missed));
    // Persona 0 was slashed out of the shard by the connect at
    // `last_block(M + 1)`. Its draws of M + 1 were issued below that
    // height, so they count and the epoch has its row; the slash is not
    // repeated, because the open interval ends its standing. Its draws of
    // M + 2 were issued above it: issued, folded into the digest the pass
    // checked, and not counted.
    assert_eq!(outcome(0, m + 1), Some(SettlementOutcome::Missed));
    assert_eq!(outcome(0, m + 2), None);
    assert_eq!(
        snap.issued_draws(epoch(m + 2))
            .expect("read")
            .iter()
            .filter(|d| d.persona == id(0))
            .count(),
        3,
        "the draws were issued"
    );
    // Personas 1 and 2 were slashed one epoch later, by the connect at
    // `last_block(M + 2)`, so their draws of M + 2 still count.
    assert_eq!(outcome(1, m + 2), Some(SettlementOutcome::Missed));
    drop(snap);
    chain.finish();
}

/// Settlement of an epoch whose stored draws do not fold to its digest is
/// the validator's `Corrupt`, and the store's SI-25 — never a slash and
/// never a refusal of the block (specification §9.5 check 1). Each of the
/// three ways the index can drift from the digest admission left.
#[test]
fn an_index_that_does_not_fold_to_its_digest_halts_the_slash_pass() {
    type Tamper = fn(&ChainStore, SettlementEpoch);
    // A draw the digest never folded.
    fn a_draw_gained(store: &ChainStore, epoch: SettlementEpoch) {
        let mut extra = planned_draws(epoch.to_raw(), 2, every_epoch_missed)[0];
        extra.draw = 9;
        let digest = store.begin_read().unwrap().issued_digest(epoch).unwrap();
        store
            .regtest_issue_draws(Trust::UNANCHORED, epoch, &[extra], digest)
            .expect("issued");
    }
    // The digest cell changed under its rows.
    fn the_digest_changed(store: &ChainStore, epoch: SettlementEpoch) {
        store
            .regtest_issue_draws(Trust::UNANCHORED, epoch, &[], IssuedDigest::ZERO)
            .expect("written");
    }
    // A row lost: removed beneath the door.
    fn a_draw_lost(store: &ChainStore, epoch: SettlementEpoch) {
        let lost = planned_draws(epoch.to_raw(), 2, every_epoch_missed)[0];
        let out: Result<(), TestErr> = store.write(|batch| {
            // Bound to a row no check names: the fixture knows the key is
            // there, so the bound row is never armed.
            let mut index = batch.open_remove_table(
                crate::schema::ARCHIVAL_ISSUED_DRAW,
                StoreInvariant::TipMismatch,
            )?;
            let key = crate::ids::IssuedDrawKey::new(
                epoch,
                lost.persona,
                lost.shard,
                lost.issuing_height,
                lost.draw,
            );
            index.remove(key.key())?;
            Ok(())
        });
        out.expect("removed");
    }
    for (label, tamper) in [
        ("slash-drift-gained", a_draw_gained as Tamper),
        ("slash-drift-digest", the_digest_changed as Tamper),
        ("slash-drift-lost", a_draw_lost as Tamper),
    ] {
        let epoch = SettlementEpoch::from_raw(1);
        let deadline = RULES.settlement_schedule().slash_deadline_height(1);
        let chain = SlashedChain::build_with(label, 2, deadline - 1, every_epoch_missed);
        tamper(&chain.store, epoch);
        let out: Result<(), TestErr> = chain.store.write(|batch| {
            let view = batch.chain_view();
            let Err(corrupt) = chain.grown.judge_empty_or_corrupt(&view, &RULES)? else {
                panic!("{label}: the pass settled a drifted index");
            };
            assert_eq!(
                corrupt,
                Corrupt::SettlementIntegrity {
                    epoch,
                    check: SettlementCheck::IssuedIndexDigest,
                },
                "{label}"
            );
            Err(batch.refuse_corrupt(corrupt).into())
        });
        let TestErr::Store(message) = out.expect_err("the batch is refused") else {
            panic!("{label}: aborted, not refused");
        };
        assert!(
            message.contains("do not fold to archival_issued_digest"),
            "{label}: {message}"
        );
        chain.finish();
    }
}

/// The rows are journaled with the block that settled them: popping the
/// deadline connect takes the epoch's rows and the watermark back, and
/// leaves the draws, which the door wrote outside any block.
#[test]
fn popping_the_deadline_connect_unsettles_the_epoch() {
    let epoch = SettlementEpoch::from_raw(1);
    let deadline = RULES.settlement_schedule().slash_deadline_height(1);
    let chain = SlashedChain::build_with("slash-pop-settlement", 2, deadline, every_epoch_missed);
    let shard = ShardId::from_raw(0);
    let rows = |store: &ChainStore| -> Vec<Option<SettlementRow>> {
        let snap = store.begin_read().expect("read");
        ids_in_table_order(2)
            .iter()
            .map(|p| snap.settlement_row(p, shard, epoch).expect("read"))
            .collect()
    };
    let missed = Some(SettlementRow::settle(0, 3).expect("a row"));
    assert_eq!(rows(&chain.store), [missed, missed]);
    let popped: Result<Popped, TestErr> = chain.store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        popped.expect("pops").height,
        BlockHeight::from_raw(deadline)
    );
    assert_eq!(
        rows(&chain.store),
        [None, None],
        "the rows went with the block"
    );
    let snap = chain.store.begin_read().expect("read");
    assert_eq!(
        snap.last_settled_slash_epoch().expect("read"),
        Some(SettlementEpoch::from_raw(0)),
        "the watermark is the epoch before"
    );
    assert_eq!(snap.issued_draws(epoch).expect("read").len(), 6);
    drop(snap);
    chain.finish();
}

/// An epoch settles once. A row already under a pair's key when the pass
/// writes it is SI-25 at the insert, before any journal entry.
#[test]
fn a_settlement_row_already_recorded_refuses_the_second_write() {
    let epoch = SettlementEpoch::from_raw(1);
    let deadline = RULES.settlement_schedule().slash_deadline_height(1);
    let mut chain =
        SlashedChain::build_with("slash-settled-twice", 2, deadline - 1, every_epoch_missed);
    let p = Persona::at(slot(0)).id();
    let planted: Result<(), TestErr> = chain.store.write(|batch| {
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_SETTLEMENT)?
            .upsert(
                crate::ids::SettlementKey::new(p, ShardId::from_raw(0), epoch).key(),
                SettlementRow::settle(2, 3)
                    .expect("a row")
                    .encoded()
                    .as_encoded(),
            )?;
        Ok(())
    });
    planted.expect("planted");
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = chain.grown.judge_listing(&view, &RULES, &[])?;
        batch.connect(judged, RULES)?;
        Ok(())
    });
    let TestErr::Store(message) = out.expect_err("the connect is refused") else {
        panic!("aborted, not refused");
    };
    assert!(
        message.contains("an epoch settles once"),
        "the insert names SI-25: {message}"
    );
    assert_eq!(
        StoreInvariant::SettlementNotSound {
            epoch,
            observed: SettlementFault::AlreadySettled {
                persona: p,
                shard: ShardId::from_raw(0),
            },
        }
        .row(),
        25
    );
    chain.finish();
}
