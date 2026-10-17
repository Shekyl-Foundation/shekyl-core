// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The drawable set through the store (`SO-D12` increment 2): the digest
//! each open writes, the Release journal each Release writes, the walk that
//! rebuilds the set from them at a later tip, and the settlement check that
//! compares the two.
//!
//! The chain is the slash-scan harness's (the parent module): four
//! complete-tree personas join in epoch 0 under `SEB 100 / cap 50`, and
//! the padding credits close shard 0 inside epoch 0. Shard 0 is closed and
//! final from height `close + 50`, so `D(1)` is empty and `D(2)` holds the
//! four `(P, 0)` pairs. Two of the personas release:
//!
//! - slot 3 at [`FIRST_RELEASE`], inside epoch 2 — above `h_open(2)`, so the
//!   walk for epoch 2 undoes it, and below `h_open(3)`, so epoch 3 does not
//!   hold the pair;
//! - slot 2 at [`h_open`]`(3)` itself — undone for epoch 2, and **applied**
//!   for epoch 3, whose open block it is in.
//!
//! The credits are slots 0 and 1's, so the two releasing personas never
//! served and CEN-J16's cooldown is vacuous for them. No draw is issued:
//! the check runs at every settlement whether anything was drawn or not.
//!
//! The rules-side arms — the undo of each event kind, the order, the
//! filters, a Reinstate — are `shekyl-chain-rules`' `drawable_tests.rs`, on
//! plain data. A slash inside an epoch is witnessed on this harness by
//! `the_window_passes_over_an_unobserved_epoch_and_counts_a_served_one`
//! (`settlement_slash_tests.rs`): its chain runs one epoch past the
//! epoch-`M` slash, whose complete-tree demotions sit above `h_open(M + 1)`,
//! and the settlement of `M + 1` checks the walk that undoes them.

use shekyl_chain_rules::{
    drawable_epoch_walked_back, ChainView as _, DrawableEpoch, DrawableEpochFault, HeaderView as _,
};
use shekyl_types::archival::{DrawableDigest, ReleasedRecord};

use crate::codec::BondRecord;

use super::*;

/// The first Release: slot 3, half way through epoch 2.
const FIRST_RELEASE: u64 = 250;
/// The persona released at [`FIRST_RELEASE`].
const FIRST: u32 = 3;
/// The persona released in epoch 3's open block.
const SECOND: u32 = 2;

fn h_open(epoch: u64) -> u64 {
    RULES.settlement_schedule().open_height(epoch)
}

/// Every complete-tree record's balance: the floor of one bond.
const BONDED: u64 = ARCHIVAL_BOND_FLOOR_ATOMIC;

/// What block `h` lists after the harness's own epoch-0 listing: the two
/// Releases, and nothing else.
fn releases_at(h: u64) -> Vec<Listed> {
    if h == FIRST_RELEASE {
        vec![Listed::Release {
            slot: FIRST,
            bonded_total: BONDED,
        }]
    } else if h == h_open(3) {
        vec![Listed::Release {
            slot: SECOND,
            bonded_total: BONDED,
        }]
    } else {
        Vec::new()
    }
}

fn no_draws(_: u64, _: u64) -> Option<&'static [bool]> {
    None
}

/// Connect the block at the chain's next height, listing `listed`.
fn connect(chain: &mut SlashedChain, listed: &[Listed]) {
    let txs = chain.grown.realise(listed);
    let grown = &mut chain.grown;
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let judged = grown.judge_listing(&view, &RULES, &txs)?;
        batch.connect(judged, RULES)?;
        Ok(())
    });
    out.expect("the block connects");
}

/// The chain through `through`, with the two Releases connected where
/// [`releases_at`] puts them.
fn released_chain(label: &str, through: u64) -> SlashedChain {
    let mut chain = SlashedChain::build_with(label, WITNESS_PERSONAS, FIRST_RELEASE - 1, no_draws);
    for h in FIRST_RELEASE..=through {
        connect(&mut chain, &releases_at(h));
    }
    chain
}

/// The walk for `epoch` over the committed chain, under the floor the next
/// block's transition would read with. Read in a batch that is aborted, so
/// it writes nothing.
fn walked(store: &ChainStore, epoch: u64) -> Option<DrawableEpoch> {
    let mut walked = None;
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let tip = view.tip()?.expect("a built chain has a tip").height;
        let connecting = tip.checked_add(BlockCount::ONE).expect("fits");
        let floor = SlashLogFloor::under(
            connecting,
            RULES.settlement_schedule().blocks(),
            RULES.reorg_cap(),
        );
        walked = drawable_epoch_walked_back(
            &view,
            SettlementEpoch::from_raw(epoch),
            RULES.settlement_schedule(),
            RULES.reorg_cap(),
            floor,
        )
        .expect("the walk reads");
        Err(TestErr::Abort)
    });
    assert!(matches!(out, Err(TestErr::Abort)));
    walked
}

fn recorded(store: &ChainStore, epoch: u64) -> Option<DrawableDigest> {
    store
        .begin_read()
        .expect("read")
        .drawable_digest(SettlementEpoch::from_raw(epoch))
        .expect("read")
}

fn personas_of(drawable: &DrawableEpoch) -> Vec<PCanonicalId> {
    (0..drawable.len())
        .map(|i| drawable.pair(i).expect("below len").persona)
        .collect()
}

/// **The two derivations agree at every height** from `h_open(E)` to the
/// pass that settles `E`, on a chain with a Release above the open and a
/// Release in the open block, for epochs 2 and 3. The digest the open
/// wrote (derivation 1, over the open block's post-state) is compared with
/// the walk from each later tip (derivation 2, over tip and the journal).
/// Both settlement passes, at `399` and `499`, run the same comparison and
/// connect.
///
/// The sets are the ones §4.1 defines: epoch 2 holds all four personas,
/// both releases undone; epoch 3 holds neither releasing persona — one
/// released before its open, one in it.
///
/// Red edits: write no journal row (the walk for epoch 2 loses slot 3 once
/// it has released); read the journal for derivation 1 too, or not apply
/// the open block's own Release (epoch 3 holds slot 2); undo events at
/// `h_open` itself in the walk (epoch 3's walk restores slot 2).
#[test]
fn the_two_derivations_agree_at_every_height_across_releases() {
    let schedule = RULES.settlement_schedule();
    let settles_3 = schedule.slash_deadline_height(3);
    let mut chain =
        SlashedChain::build_with("drawable-agree", WITNESS_PERSONAS, h_open(2) - 1, no_draws);
    for h in h_open(2)..=settles_3 {
        connect(&mut chain, &releases_at(h));
        for epoch in [2, 3] {
            if h < h_open(epoch) {
                continue;
            }
            let walked = walked(&chain.store, epoch).expect("the epoch has opened");
            assert_eq!(
                Some(walked.digest()),
                recorded(&chain.store, epoch),
                "epoch {epoch} rebuilt at tip {h}"
            );
        }
    }
    let snap = chain.store.begin_read().expect("read");
    assert_eq!(
        snap.last_settled_slash_epoch().expect("read"),
        Some(SettlementEpoch::from_raw(3)),
        "both settlement passes ran their check and connected"
    );
    drop(snap);

    let all: Vec<PCanonicalId> = ids_in_table_order(WITNESS_PERSONAS);
    let epoch_2 = walked(&chain.store, 2).expect("opened");
    assert_eq!(personas_of(&epoch_2), all, "epoch 2 keeps both releasers");
    let released = [Persona::at(FIRST).id(), Persona::at(SECOND).id()];
    let epoch_3 = walked(&chain.store, 3).expect("opened");
    let kept: Vec<PCanonicalId> = all
        .iter()
        .copied()
        .filter(|p| !released.contains(p))
        .collect();
    assert_eq!(personas_of(&epoch_3), kept, "epoch 3 holds neither");
    chain.finish();
}

/// Each Release writes its record's pre-image under `(height, persona)`:
/// the record exactly as it stood, its complete tree included. A read
/// strictly above a height returns the rows above it in key order.
/// Red edit: journal the post-image.
#[test]
fn a_release_journals_the_record_it_replaced() {
    let chain = released_chain("drawable-journal", h_open(3));
    let snap = chain.store.begin_read().expect("read");
    let rows = snap
        .release_journal_after(BlockHeight::from_raw(h_open(2)), SlashLogFloor::NONE)
        .expect("read");
    let heights: Vec<(u64, PCanonicalId)> = rows
        .iter()
        .map(|r| (r.height.to_raw(), r.persona))
        .collect();
    assert_eq!(
        heights,
        [
            (FIRST_RELEASE, Persona::at(FIRST).id()),
            (h_open(3), Persona::at(SECOND).id()),
        ]
    );
    for ReleasedRecord {
        persona, pre_image, ..
    } in &rows
    {
        assert!(pre_image.is_complete_tree(), "the pre-image holds the tree");
        assert_eq!(pre_image.bonded_total, AtomicUnits::from_raw(BONDED));
        let now = snap.bond_record(persona).expect("read").expect("kept");
        assert!(!now.is_complete_tree(), "the record at tip is emptied");
        assert_eq!(now.receipt_sign_pk, pre_image.receipt_sign_pk);
    }
    assert!(snap
        .release_journal_after(BlockHeight::from_raw(h_open(3)), SlashLogFloor::NONE)
        .expect("read")
        .is_empty());
    drop(snap);
    chain.finish();
}

/// **A journal or a digest that changed after the open halts the
/// settlement pass**, through the validator's `Corrupt` and the store's
/// SI-29 or SI-30, and never as a verdict on the block. Each tamper is made
/// in the batch that then judges the settling block, on a chain of its
/// own: the refusal halts the writer. The walk is the real one over the
/// tampered rows. The same chain untampered settles the epoch: that is
/// [`the_two_derivations_agree_at_every_height_across_releases`].
///
/// - The pre-image of slot 3's Release, with its holdings emptied: epoch 2
///   loses a pair. Drift.
/// - The same pre-image with one byte of its receipt key changed (an edit
///   that still parses): the pairs are the same and the key is not. Drift.
/// - A slash row planted under slot 0, a complete tree at tip, as a
///   complete-tree demotion above the open: the record cannot have been
///   left by it. The walk refuses it.
/// - The digest cell itself. Drift.
/// - The digest removed. Missing.
#[test]
fn a_journal_that_changed_after_the_open_halts_the_settlement() {
    type Tamper = fn(&WriteBatch<'_, '_>) -> Result<(), StoreError>;
    let epoch = SettlementEpoch::from_raw(2);
    let settles = RULES.settlement_schedule().slash_deadline_height(2);

    fn pre_image(batch: &WriteBatch<'_, '_>) -> Result<BondRecord, StoreError> {
        let key = crate::ids::ReleaseJournalKey::new(
            BlockHeight::from_raw(FIRST_RELEASE),
            Persona::at(FIRST).id(),
        );
        Ok(batch
            .chain_view()
            .release_journal_after(
                BlockHeight::from_raw(FIRST_RELEASE - 1),
                SlashLogFloor::NONE,
            )?
            .into_iter()
            .find(|r| r.persona == key.persona())
            .expect("journaled")
            .pre_image)
    }
    fn rewrite(batch: &WriteBatch<'_, '_>, record: &BondRecord) -> Result<(), StoreError> {
        let key = crate::ids::ReleaseJournalKey::new(
            BlockHeight::from_raw(FIRST_RELEASE),
            Persona::at(FIRST).id(),
        );
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_RELEASE_JOURNAL)?
            .upsert(key.key(), record.encoded().as_encoded())?;
        Ok(())
    }
    fn holdings_emptied(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        let mut record = pre_image(batch)?;
        record.holdings =
            shekyl_types::archival::Holdings::shard_set(Vec::new()).expect("the empty set");
        rewrite(batch, &record)
    }
    fn key_changed(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        let mut record = pre_image(batch)?;
        let mut bytes = *record.receipt_sign_pk.as_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        // The last byte is the FN-DSA key's last coefficient bits. The
        // edit leaves a key for this persona's: were it not one, the walk
        // would refuse the record (`Construction`), not report drift, and
        // the case's expected `Corrupt` would not match.
        record.receipt_sign_pk = shekyl_types::archival::ReceiptSignPk::from_bytes(bytes);
        rewrite(batch, &record)
    }
    fn slash_planted(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        let entry = SlashLogEntry {
            persona: Persona::at(0).id(),
            shard: ShardId::from_raw(0),
            epoch: SettlementEpoch::from_raw(1),
            holding: SlashedHolding::CompleteTree,
        };
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_SLASH_LOG)?
            .upsert(
                crate::ids::SlashLogKey::new(BlockHeight::from_raw(FIRST_RELEASE + 1), 0).key(),
                entry.encoded().as_encoded(),
            )?;
        Ok(())
    }
    fn digest_changed(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        batch
            .open_upsert_table(crate::schema::ARCHIVAL_DRAWABLE_DIGEST)?
            .upsert(
                2,
                DrawableDigest::from_bytes([0x5a; 32])
                    .encoded()
                    .as_encoded(),
            )?;
        Ok(())
    }
    fn digest_removed(batch: &WriteBatch<'_, '_>) -> Result<(), StoreError> {
        batch
            .open_remove_table(
                crate::schema::ARCHIVAL_DRAWABLE_DIGEST,
                StoreInvariant::TipMismatch,
            )?
            .remove(2)?;
        Ok(())
    }

    let drift = Corrupt::SettlementIntegrity {
        epoch,
        check: SettlementCheck::DrawableDrift,
    };
    let cases: [(&str, Tamper, Corrupt, &str); 5] = [
        (
            "holdings",
            holdings_emptied,
            drift,
            "does not digest to archival_drawable_digest",
        ),
        (
            "key",
            key_changed,
            drift,
            "does not digest to archival_drawable_digest",
        ),
        (
            "slash",
            slash_planted,
            Corrupt::DrawableEpoch {
                epoch,
                why: DrawableEpochFault::SlashNotUndoable {
                    persona: Persona::at(0).id(),
                    shard: ShardId::from_raw(0),
                },
            },
            "cannot have left the record",
        ),
        (
            "digest",
            digest_changed,
            drift,
            "does not digest to archival_drawable_digest",
        ),
        (
            "removed",
            digest_removed,
            Corrupt::SettlementIntegrity {
                epoch,
                check: SettlementCheck::DrawableDigestMissing,
            },
            "holds no digest for epoch 2",
        ),
    ];
    for (label, tamper, expected, message) in cases {
        // A refusal latches the writer halt, so each case has its chain.
        let chain = released_chain(&format!("drawable-tamper-{label}"), settles - 1);
        let out: Result<(), TestErr> = chain.store.write(|batch| {
            tamper(batch)?;
            let view = batch.chain_view();
            let Err(corrupt) = chain.grown.judge_empty_or_corrupt(&view, &RULES)? else {
                panic!("{label}: the pass settled over a changed journal");
            };
            assert_eq!(corrupt, expected, "{label}");
            Err(batch.refuse_corrupt(corrupt).into())
        });
        let TestErr::Store(refused) = out.expect_err("the batch is refused") else {
            panic!("{label}: aborted, not refused");
        };
        assert!(refused.contains(message), "{label}: {refused}");
        chain.finish();
    }
}

/// **The digest is undone with the open that wrote it**: popping
/// `h_open(3)` removes epoch 3's digest and the Release journaled in that
/// block, and connecting the same block again writes the same digest and
/// the same row. Red edit: write either outside the journal.
#[test]
fn popping_an_open_removes_its_digest_and_reconnecting_writes_it_again() {
    let mut chain = released_chain("drawable-pop", h_open(3));
    let journal = |store: &ChainStore| {
        store
            .begin_read()
            .expect("read")
            .release_journal_after(BlockHeight::from_raw(h_open(3) - 1), SlashLogFloor::NONE)
            .expect("read")
    };
    let digest = recorded(&chain.store, 3).expect("the open wrote it");
    assert_eq!(journal(&chain.store).len(), 1, "slot 2's Release");

    let popped: Result<Popped, TestErr> = chain.store.write(|batch| Ok(batch.pop()?));
    assert_eq!(
        popped.expect("pops").height,
        BlockHeight::from_raw(h_open(3))
    );
    chain.grown.pop();
    assert_eq!(
        recorded(&chain.store, 3),
        None,
        "the digest went with the block"
    );
    assert!(journal(&chain.store).is_empty(), "and so did the row");
    assert!(
        recorded(&chain.store, 2).is_some(),
        "epoch 2's is untouched"
    );

    connect(&mut chain, &releases_at(h_open(3)));
    assert_eq!(recorded(&chain.store, 3), Some(digest));
    assert_eq!(journal(&chain.store).len(), 1);
    chain.finish();
}

/// A walk whose floor is above its open is refused at the enumerator, and
/// the store refuses the journal read beneath it (SI-28), as it refuses the
/// slash log's (SI-26). The schedule keeps a settlement's walk inside the
/// window (`WALK_BACK_EPOCHS`), so this is the floor handed in by a caller.
/// Red edit: drop either check.
#[test]
fn a_walk_below_the_floor_is_refused_and_so_is_the_read() {
    let chain = released_chain("drawable-floor", FIRST_RELEASE);
    let floor = SlashLogFloor::under(
        BlockHeight::from_raw(
            SlashLogFloor::window(RULES.settlement_schedule().blocks(), RULES.reorg_cap())
                .expect("fits")
                .to_raw()
                + h_open(2)
                + 5,
        ),
        RULES.settlement_schedule().blocks(),
        RULES.reorg_cap(),
    );
    let kept_from = floor.height().expect("a floor");
    assert!(kept_from.to_raw() > h_open(2) + 1);
    let out: Result<(), TestErr> = chain.store.write(|batch| {
        let view = batch.chain_view();
        let refused = drawable_epoch_walked_back(
            &view,
            SettlementEpoch::from_raw(2),
            RULES.settlement_schedule(),
            RULES.reorg_cap(),
            floor,
        );
        assert!(
            matches!(
                refused,
                Err(shekyl_chain_rules::ViewRead::Corrupt(
                    Corrupt::DrawableEpoch {
                        why: DrawableEpochFault::BelowFloor { .. },
                        ..
                    }
                ))
            ),
            "{refused:?}"
        );
        Err(TestErr::Abort)
    });
    assert!(matches!(out, Err(TestErr::Abort)));
    let snap = chain.store.begin_read().expect("read");
    let asked = BlockHeight::from_raw(h_open(2));
    let journal = snap.release_journal_after(asked, floor).map(drop);
    assert!(
        matches!(
            journal,
            Err(StoreError::InvariantViolated(StoreInvariant::ReleaseJournalReadBelowFloor { asked: a, floor: f }))
                if a == asked && f == kept_from
        ),
        "{journal:?}"
    );
    let log = snap.slash_log_rows_after(asked, floor).map(drop);
    assert!(
        matches!(
            log,
            Err(StoreError::InvariantViolated(StoreInvariant::SlashLogReadBelowFloor { asked: a, floor: f }))
                if a == asked && f == kept_from
        ),
        "{log:?}"
    );
    drop(snap);
    chain.finish();
}
